import {
  SSMClient,
  GetParameterCommand,
  GetParametersByPathCommand,
  PutParameterCommand,
} from '@aws-sdk/client-ssm';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import { withCache, type Secret, type SecretProvider, type SecretStore } from '../secret-provider.js';

const SECRET_CACHE_TTL_MS = 300_000; // 5 minutes
const CREDENTIALS_REFRESH_MS = 2_700_000; // 45 minutes (STS session is 1h by default)

interface AssumedCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  assumedAt: number;
}

export interface AwsProviderOptions {
  label: string;
  region?: string;
  roleArn?: string;
}

/**
 * The error code of an AWS SDK error. Depending on the service and the
 * `@aws-sdk/core` version it is on `name` or on `Code`, so check both.
 */
export function awsErrorCode(err: unknown): string {
  const name = err instanceof Error ? err.name : '';
  const code = (err as { Code?: unknown } | null)?.Code;
  return [name, typeof code === 'string' ? code : ''].find(c => c && c !== 'Error') ?? '';
}

/**
 * AWS secret backend: per-agent secrets in SSM Parameter Store, shared secrets
 * in Secrets Manager. When a role ARN is configured, it is assumed via STS
 * before any read or write.
 */
class AwsBackend {
  private readonly basePath: string;
  private readonly region: string;
  private assumedCreds: AssumedCredentials | null = null;

  constructor(private readonly opts: AwsProviderOptions) {
    this.basePath = `/liv/agents/${opts.label}/user-secrets/`;
    this.region = opts.region ?? process.env.AWS_REGION ?? 'ap-southeast-2';
  }

  /** SSM client options — includes endpoint override for LocalStack in dev */
  private get ssmBaseOptions(): Record<string, unknown> {
    const opts: Record<string, unknown> = { region: this.region };
    if (process.env.AWS_ENDPOINT_URL) {
      opts.endpoint = process.env.AWS_ENDPOINT_URL;
    }
    return opts;
  }

  /** Resolve AWS client options, assuming the broker role if configured */
  private async getAwsClientOptions(): Promise<Record<string, unknown>> {
    if (!this.opts.roleArn) {
      // No role to assume — use default credentials (task role or env creds)
      return this.ssmBaseOptions;
    }

    // Refresh assumed credentials if expired or not yet assumed
    if (!this.assumedCreds || Date.now() - this.assumedCreds.assumedAt > CREDENTIALS_REFRESH_MS) {
      const sts = new STSClient({ region: this.region });
      const result = await sts.send(new AssumeRoleCommand({
        RoleArn: this.opts.roleArn,
        RoleSessionName: `secret-proxy-${this.opts.label}`,
        DurationSeconds: 3600,
      }));

      if (!result.Credentials?.AccessKeyId || !result.Credentials.SecretAccessKey || !result.Credentials.SessionToken) {
        throw new Error('STS AssumeRole did not return credentials');
      }

      this.assumedCreds = {
        accessKeyId: result.Credentials.AccessKeyId,
        secretAccessKey: result.Credentials.SecretAccessKey,
        sessionToken: result.Credentials.SessionToken,
        assumedAt: Date.now(),
      };
      console.log(`Assumed broker role: ${this.opts.roleArn}`);
    }

    return {
      ...this.ssmBaseOptions,
      credentials: {
        accessKeyId: this.assumedCreds.accessKeyId,
        secretAccessKey: this.assumedCreds.secretAccessKey,
        sessionToken: this.assumedCreds.sessionToken,
      },
    };
  }

  private async getSSMClient(): Promise<SSMClient> {
    return new SSMClient(await this.getAwsClientOptions());
  }

  private async getSecretsManagerClient(): Promise<SecretsManagerClient> {
    return new SecretsManagerClient(await this.getAwsClientOptions());
  }

  /** Shared secret from Secrets Manager at `liv/{name}`, or null if absent. */
  async getShared(name: string): Promise<Secret | null> {
    const sm = await this.getSecretsManagerClient();
    try {
      const result = await sm.send(new GetSecretValueCommand({
        SecretId: `liv/${name}`,
      }));
      return result.SecretString === undefined ? null : { value: result.SecretString };
    } catch (err: unknown) {
      if (awsErrorCode(err) === 'ResourceNotFoundException') return null;
      throw err;
    }
  }

  /** Per-agent secret from SSM, or null if absent. */
  async get(name: string): Promise<Secret | null> {
    const ssm = await this.getSSMClient();
    try {
      const result = await ssm.send(new GetParameterCommand({
        Name: this.basePath + name,
        WithDecryption: true,
      }));
      const value = result.Parameter?.Value;
      return value === undefined ? null : { value };
    } catch (err: unknown) {
      if (awsErrorCode(err) === 'ParameterNotFound') return null;
      throw err;
    }
  }

  /** Check if a secret exists (without decrypting) */
  async exists(name: string): Promise<boolean> {
    const ssm = await this.getSSMClient();
    try {
      await ssm.send(new GetParameterCommand({
        Name: this.basePath + name,
        WithDecryption: false,
      }));
      return true;
    } catch (err: unknown) {
      if (awsErrorCode(err) === 'ParameterNotFound') return false;
      throw err;
    }
  }

  /** Overwrite a secret value */
  async put(name: string, value: string): Promise<void> {
    const ssm = await this.getSSMClient();
    await ssm.send(new PutParameterCommand({
      Name: this.basePath + name,
      Value: value,
      Type: 'SecureString',
      Overwrite: true,
    }));
  }

  /** List all secret names in the agent's store */
  async list(): Promise<string[]> {
    const ssm = await this.getSSMClient();
    const names: string[] = [];
    let nextToken: string | undefined;

    do {
      const result = await ssm.send(new GetParametersByPathCommand({
        Path: this.basePath,
        Recursive: false,
        WithDecryption: false,
        NextToken: nextToken,
      }));

      for (const param of result.Parameters ?? []) {
        if (param.Name) {
          // Strip the base path prefix to get just the secret name
          const name = param.Name.slice(this.basePath.length);
          if (name) names.push(name);
        }
      }

      nextToken = result.NextToken;
    } while (nextToken);

    return names;
  }
}

export function createAwsProvider(opts: AwsProviderOptions): SecretProvider {
  const backend = new AwsBackend(opts);
  const secrets: SecretStore = {
    get: name => backend.get(name),
    exists: name => backend.exists(name),
    list: () => backend.list(),
    put: (name, value) => backend.put(name, value),
  };
  return {
    name: 'aws',
    secrets: withCache(secrets, SECRET_CACHE_TTL_MS),
    shared: { get: name => backend.getShared(name) },
  };
}
