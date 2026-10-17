/**
 * `COATCHECK_PROVIDER=file`: secrets from a JSON file,
 * `{"secrets": {"name": "value", …}, "shared": {…}}`. Values are strings
 * (multi-field secrets are JSON-encoded strings, as in every provider).
 * `put` writes a temp file in the same directory and renames it over the
 * original, so a crash never leaves a truncated file.
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  ConfigError, EnvReader,
  type CreateProvider, type ProviderContext, type Secret, type SecretProvider, type SecretStore,
} from '@coatcheck/core';

interface SecretsFile {
  secrets: Record<string, string>;
  shared: Record<string, string>;
}

export interface FileProviderConfig {
  path: string;
}

export function loadFileConfig(ctx: ProviderContext): FileProviderConfig {
  const r = new EnvReader(ctx.env);
  const file = r.string('COATCHECK_SECRETS_FILE');
  if (file === undefined) r.problems.push('COATCHECK_SECRETS_FILE is required for COATCHECK_PROVIDER=file');
  if (r.problems.length > 0) throw new ConfigError(r.problems);
  return { path: file! };
}

/** Parse and check the file's shape. Errors name the field, never a value. */
export function parseSecretsFile(text: string, source: string): SecretsFile {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new ConfigError([`${source}: not valid JSON`]);
  }
  const problems: string[] = [];
  const section = (key: string): Record<string, string> => {
    const v = (raw as Record<string, unknown> | null)?.[key];
    if (v === undefined) return {};
    if (typeof v !== 'object' || v === null || Array.isArray(v)) {
      problems.push(`${source}: '${key}' must be an object of name → string`);
      return {};
    }
    for (const [name, value] of Object.entries(v)) {
      if (typeof value !== 'string') problems.push(`${source}: ${key}.${name} must be a string`);
    }
    return v as Record<string, string>;
  };
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new ConfigError([`${source}: must be a JSON object with 'secrets' and/or 'shared'`]);
  }
  const unknown = Object.keys(raw).filter(k => k !== 'secrets' && k !== 'shared');
  if (unknown.length > 0) problems.push(`${source}: unknown key(s) ${unknown.join(', ')}`);
  const file = { secrets: section('secrets'), shared: section('shared') };
  if (problems.length > 0) throw new ConfigError(problems);
  return file;
}

/**
 * Reads the file on every call (pair with core's `withCache`), so edits are
 * picked up without a restart. Writes are serialised within this process.
 */
export async function createFileProvider(config: FileProviderConfig): Promise<SecretProvider> {
  const load = async (): Promise<SecretsFile> =>
    parseSecretsFile(await fs.readFile(config.path, 'utf8'), `COATCHECK_SECRETS_FILE '${config.path}'`);
  await load(); // fail startup on a missing or malformed file

  const own = (o: Record<string, string>, k: string) => Object.prototype.hasOwnProperty.call(o, k);
  const lookup = (o: Record<string, string>, name: string): Secret | null =>
    own(o, name) ? { value: o[name] } : null;

  let writes: Promise<void> = Promise.resolve();
  const put = (name: string, value: string): Promise<void> => {
    const next = writes.then(async () => {
      const file = await load();
      file.secrets[name] = value;
      const tmp = path.join(path.dirname(config.path), `.${path.basename(config.path)}.${randomBytes(6).toString('hex')}.tmp`);
      try {
        await fs.writeFile(tmp, JSON.stringify(file, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
        await fs.rename(tmp, config.path);
      } catch (err) {
        await fs.rm(tmp, { force: true });
        throw err;
      }
    });
    writes = next.catch(() => undefined);
    return next;
  };

  const secrets: SecretStore = {
    get: async name => lookup((await load()).secrets, name),
    exists: async name => own((await load()).secrets, name),
    list: async () => Object.keys((await load()).secrets).sort(),
    put,
  };
  return {
    name: 'file',
    secrets,
    shared: { get: async name => lookup((await load()).shared, name) },
  };
}

const createProvider: CreateProvider = async ctx => createFileProvider(loadFileConfig(ctx));
export default createProvider;
