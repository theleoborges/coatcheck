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
import type { CreateProvider, ProviderContext, Secret, SecretProvider, SecretStore } from '@coatcheck/core';
import { ConfigError, EnvReader, interpolateAgentId } from '@coatcheck/core';

const DEFAULT_SSM_PREFIX = '/coatcheck/secrets/';
const DEFAULT_SHARED_PREFIX = 'coatcheck/';
const SSM_PREFIX = /^\/(?:[A-Za-z0-9_.-]+\/)*$/;
const SHARED_PREFIX = /^[A-Za-z0-9_./+=@-]*$/;
const ROLE_SESSION_NAME = /^[\w+=,.@-]{2,64}$/;
const CREDENTIALS_REFRESH_MS = 2_700_000; // 45 minutes (STS session is 1h by default)

interface AssumedCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  assumedAt: number;
}

export interface AwsProviderConfig {
  /** SSM path prefix for per-agent secrets, ending in `/`. */
  ssmPrefix: string;
  /** Secrets Manager name prefix for shared secrets. */
  sharedPrefix: string;
  /** Broker role to assume before any call; unset uses the default credential chain. */
  roleArn?: string;
  roleSessionName: string;
}

/**
 * Parse the AWS provider's settings from the environment. Region, endpoint
 * (`AWS_ENDPOINT_URL`) and credentials are left to the SDK's default chain.
 */
export function loadAwsConfig(ctx: ProviderContext): AwsProviderConfig {
  const r = new EnvReader(ctx.env);
  const ssmPrefix = interpolateAgentId(
    r.string('COATCHECK_AWS_SSM_PREFIX') ?? DEFAULT_SSM_PREFIX, ctx.agentId, 'COATCHECK_AWS_SSM_PREFIX', r.problems);
  const sharedPrefix = interpolateAgentId(
    r.string('COATCHECK_AWS_SHARED_PREFIX') ?? DEFAULT_SHARED_PREFIX, ctx.agentId, 'COATCHECK_AWS_SHARED_PREFIX', r.problems);
  const roleSessionName = interpolateAgentId(
    r.string('COATCHECK_AWS_ROLE_SESSION_NAME') ?? (ctx.agentId ? 'coatcheck-{agentId}' : 'coatcheck'),
    ctx.agentId, 'COATCHECK_AWS_ROLE_SESSION_NAME', r.problems);
  const roleArn = r.string('COATCHECK_AWS_ROLE_ARN');

  if (r.problems.length === 0) {
    if (!SSM_PREFIX.test(ssmPrefix)) {
      r.problems.push(`COATCHECK_AWS_SSM_PREFIX must be an SSM path starting and ending with '/' (got '${ssmPrefix}')`);
    }
    if (!SHARED_PREFIX.test(sharedPrefix)) {
      r.problems.push(`COATCHECK_AWS_SHARED_PREFIX contains characters Secrets Manager names cannot (got '${sharedPrefix}')`);
    }
    if (!ROLE_SESSION_NAME.test(roleSessionName)) {
      r.problems.push(`COATCHECK_AWS_ROLE_SESSION_NAME must be 2-64 characters of [\\w+=,.@-] (got '${roleSessionName}')`);
    }
  }
  if (roleArn !== undefined && !/^arn:aws[a-z-]*:iam::\d{12}:role\/.+$/.test(roleArn)) {
    r.problems.push('COATCHECK_AWS_ROLE_ARN must be an IAM role ARN');
  }

  if (r.problems.length > 0) throw new ConfigError(r.problems);
  return { ssmPrefix, sharedPrefix, roleArn, roleSessionName };
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
  private assumedCreds: AssumedCredentials | null = null;

  constructor(private readonly opts: AwsProviderConfig) {
    this.basePath = opts.ssmPrefix;
  }

  /**
   * Resolve AWS client options, assuming the broker role if configured.
   * Region and endpoint (`AWS_REGION`, `AWS_ENDPOINT_URL`) come from the SDK's
   * default chain.
   */
  private async getAwsClientOptions(): Promise<Record<string, unknown>> {
    if (!this.opts.roleArn) {
      // No role to assume — use default credentials (task role or env creds)
      return {};
    }

    // Refresh assumed credentials if expired or not yet assumed
    if (!this.assumedCreds || Date.now() - this.assumedCreds.assumedAt > CREDENTIALS_REFRESH_MS) {
      const sts = new STSClient({});
      const result = await sts.send(new AssumeRoleCommand({
        RoleArn: this.opts.roleArn,
        RoleSessionName: this.opts.roleSessionName,
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

  /** Shared secret from Secrets Manager at `{sharedPrefix}{name}`, or null if absent. */
  async getShared(name: string): Promise<Secret | null> {
    const sm = await this.getSecretsManagerClient();
    try {
      const result = await sm.send(new GetSecretValueCommand({
        SecretId: this.opts.sharedPrefix + name,
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

export function createAwsProvider(config: AwsProviderConfig): SecretProvider {
  const backend = new AwsBackend(config);
  const secrets: SecretStore = {
    get: name => backend.get(name),
    exists: name => backend.exists(name),
    list: () => backend.list(),
    put: (name, value) => backend.put(name, value),
  };
  return {
    name: 'aws',
    secrets,
    shared: { get: name => backend.getShared(name) },
  };
}

/** `COATCHECK_PROVIDER=aws`: core loads this module and calls its default export. */
const createProvider: CreateProvider = async ctx => createAwsProvider(loadAwsConfig(ctx));
export default createProvider;
