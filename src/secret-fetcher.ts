import {
  SSMClient,
  GetParameterCommand,
  GetParametersByPathCommand,
} from '@aws-sdk/client-ssm';

const SECRET_CACHE_TTL_MS = 300_000; // 5 minutes

interface CachedSecret {
  value: string;
  fetchedAt: number;
}

/**
 * Fetches user vault secrets from SSM Parameter Store.
 * Caches values in memory with a short TTL to reduce SSM API calls.
 */
export class SecretFetcher {
  private ssm: SSMClient;
  private label: string;
  private basePath: string;
  private cache = new Map<string, CachedSecret>();

  constructor(label: string, region?: string) {
    this.label = label;
    this.basePath = `/liv/agents/${label}/user-secrets/`;
    this.ssm = new SSMClient({ region: region ?? process.env.AWS_REGION ?? 'ap-southeast-2' });
  }

  /** Get a secret value by name, or null if not found */
  async get(name: string): Promise<string | null> {
    // Check cache first
    const cached = this.cache.get(name);
    if (cached && Date.now() - cached.fetchedAt < SECRET_CACHE_TTL_MS) {
      return cached.value;
    }

    try {
      const result = await this.ssm.send(new GetParameterCommand({
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
    try {
      await this.ssm.send(new GetParameterCommand({
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
    const names: string[] = [];
    let nextToken: string | undefined;

    do {
      const result = await this.ssm.send(new GetParametersByPathCommand({
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
