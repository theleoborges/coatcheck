import { ConfigError } from './config.js';
import type { CreateProvider, ProviderContext, SecretProvider } from './secret-provider.js';

/** Built-in `COATCHECK_PROVIDER` names and the modules that implement them. */
export const BUILTIN_PROVIDERS: Readonly<Record<string, string>> = {
  aws: '@coatcheck/provider-aws',
  env: '@coatcheck/provider-env',
  file: '@coatcheck/provider-env/file',
};

/** Loads a module specifier. Injected so tests don't need installed packages. */
export type ImportModule = (specifier: string) => Promise<unknown>;

const defaultImport: ImportModule = specifier => import(specifier);

/**
 * Instantiate the provider named by `COATCHECK_PROVIDER`: a built-in name, or
 * any module specifier whose default export is a `CreateProvider`. Core has no
 * static dependency on provider packages (design: v1-decisions.md §1).
 */
export async function loadProvider(
  name: string,
  ctx: ProviderContext,
  importModule: ImportModule = defaultImport,
): Promise<SecretProvider> {
  const specifier = BUILTIN_PROVIDERS[name] ?? name;
  let mod: unknown;
  try {
    mod = await importModule(specifier);
  } catch (err) {
    const code = (err as { code?: unknown } | null)?.code;
    if (code === 'ERR_MODULE_NOT_FOUND' || code === 'MODULE_NOT_FOUND') {
      const pkg = BUILTIN_PROVIDERS[name]?.split('/').slice(0, 2).join('/');
      throw new ConfigError([pkg
        ? `COATCHECK_PROVIDER '${name}' needs ${pkg}: npm install ${pkg}`
        : `COATCHECK_PROVIDER '${name}': module not found`]);
    }
    throw err;
  }
  const create = (mod as { default?: unknown } | null)?.default;
  if (typeof create !== 'function') {
    throw new ConfigError([`COATCHECK_PROVIDER '${name}': '${specifier}' has no default-exported createProvider function`]);
  }
  return (create as CreateProvider)(ctx);
}
