import { ConfigError } from '../config.js';
import type { ProviderContext, SecretProvider } from '../secret-provider.js';
import { createAwsProvider, loadAwsConfig } from './aws.js';

/** Instantiate the provider named by `COATCHECK_PROVIDER`. */
export async function loadProvider(name: string, ctx: ProviderContext): Promise<SecretProvider> {
  switch (name) {
    case 'aws':
      return createAwsProvider(loadAwsConfig(ctx));
    default:
      throw new ConfigError([`COATCHECK_PROVIDER '${name}' is not available`]);
  }
}
