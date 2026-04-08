import {
  SSMClient,
  GetParameterCommand,
  GetParametersByPathCommand,
} from '@aws-sdk/client-ssm';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';

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

  /** Get an SSM client, assuming the proxy role if configured */
  private async getSSMClient(): Promise<SSMClient> {
    if (!this.proxyRoleArn) {
      // No role to assume — use default credentials (task role)
      return new SSMClient({ region: this.region });
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

    return new SSMClient({
      region: this.region,
      credentials: {
        accessKeyId: this.assumedCreds.accessKeyId,
        secretAccessKey: this.assumedCreds.secretAccessKey,
        sessionToken: this.assumedCreds.sessionToken,
      },
    });
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
