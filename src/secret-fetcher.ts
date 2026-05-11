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

const SECRET_CACHE_TTL_MS = 300_000; // 5 minutes
const CREDENTIALS_REFRESH_MS = 2_700_000; // 45 minutes (STS session is 1h by default)

interface CachedSecret {
  value: string;
  fetchedAt: number;
}

interface AssumedCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  assumedAt: number;
}

/**
 * Fetches user vault secrets from SSM Parameter Store.
 * When a proxy role ARN is provided, assumes that role via STS first.
 * Caches values in memory with a short TTL to reduce SSM API calls.
 */
export class SecretFetcher {
  private label: string;
  private basePath: string;
  private cache = new Map<string, CachedSecret>();
  private proxyRoleArn: string | undefined;
  private region: string;
  private assumedCreds: AssumedCredentials | null = null;

  constructor(label: string, region?: string, proxyRoleArn?: string) {
    this.label = label;
    this.basePath = `/liv/agents/${label}/user-secrets/`;
    this.region = region ?? process.env.AWS_REGION ?? 'ap-southeast-2';
    this.proxyRoleArn = proxyRoleArn ?? process.env.PROXY_ROLE_ARN;
  }

  /** SSM client options — includes endpoint override for LocalStack in dev */
  private get ssmBaseOptions(): Record<string, unknown> {
    const opts: Record<string, unknown> = { region: this.region };
    if (process.env.AWS_ENDPOINT_URL) {
      opts.endpoint = process.env.AWS_ENDPOINT_URL;
    }
    return opts;
  }

  /** Resolve AWS client options, assuming the proxy role if configured */
  private async getAwsClientOptions(): Promise<Record<string, unknown>> {
    if (!this.proxyRoleArn) {
      // No role to assume — use default credentials (task role or env creds)
      return this.ssmBaseOptions;
    }

    // Refresh assumed credentials if expired or not yet assumed
    if (!this.assumedCreds || Date.now() - this.assumedCreds.assumedAt > CREDENTIALS_REFRESH_MS) {
      const sts = new STSClient({ region: this.region });
      const result = await sts.send(new AssumeRoleCommand({
        RoleArn: this.proxyRoleArn,
        RoleSessionName: `secret-proxy-${this.label}`,
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
      console.log(`Assumed proxy role: ${this.proxyRoleArn}`);
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

  /**
   * Fetch a fleet-wide secret from AWS Secrets Manager at `liv/{name}`.
   * Used for shared API keys (e.g. Browserbase) — distinct from per-user vault entries
   * which live in SSM Parameter Store at /liv/agents/{label}/user-secrets/.
   */
  async fetchFleetSecret(name: string): Promise<string | null> {
    const sm = await this.getSecretsManagerClient();
    try {
      const result = await sm.send(new GetSecretValueCommand({
        SecretId: `liv/${name}`,
      }));
      return result.SecretString ?? null;
    } catch (err: unknown) {
      // SecretsManager error name varies by SDK version (err.name vs err.Code).
      const errName = (err instanceof Error ? err.name : '') || (err as { Code?: string })?.Code || '';
      if (errName === 'ResourceNotFoundException') {
        return null;
      }
      throw err;
    }
  }

  /** Get a secret value by name, or null if not found */
  async get(name: string): Promise<string | null> {
    // Check cache first
    const cached = this.cache.get(name);
    if (cached && Date.now() - cached.fetchedAt < SECRET_CACHE_TTL_MS) {
      return cached.value;
    }

    const ssm = await this.getSSMClient();
    try {
      const result = await ssm.send(new GetParameterCommand({
        Name: this.basePath + name,
        WithDecryption: true,
      }));

      const value = result.Parameter?.Value ?? null;
      if (value !== null) {
        this.cache.set(name, { value, fetchedAt: Date.now() });
      }
      return value;
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'ParameterNotFound') {
        return null;
      }
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
      if (err instanceof Error && err.name === 'ParameterNotFound') {
        return false;
      }
      throw err;
    }
  }

  /** Update a secret value in the vault (overwrite) and invalidate cache */
  async put(name: string, value: string): Promise<void> {
    const ssm = await this.getSSMClient();
    await ssm.send(new PutParameterCommand({
      Name: this.basePath + name,
      Value: value,
      Type: 'SecureString',
      Overwrite: true,
    }));
    // Invalidate cache so next get() reads the fresh value
    this.cache.delete(name);
  }

  /** List all secret names in the user's vault */
  async listSecrets(): Promise<string[]> {
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
