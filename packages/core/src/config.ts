/**
 * Core configuration: the only place that interprets coatcheck's environment
 * variables (design: docs/design/v1-decisions.md §4). `loadConfig` is pure — it
 * takes an env snapshot and returns a typed Config or throws a ConfigError
 * listing every problem at once.
 */

import { isValidSecretName } from './secret-provider.js';
import { EMPTY_POLICY, parsePolicy, type Policy } from './policy.js';
import net from 'node:net';
import { parseHostPattern, type HostPattern } from './host-matcher.js';
import { BUILTIN_BROWSER_ADAPTERS } from './browser-adapters.js';

/** `COATCHECK_MITM`: `bound` MITMs only hosts a ticket could be swapped for; `always` MITMs every CONNECT. */
export type MitmMode = 'bound' | 'always';

export type Env = Readonly<Record<string, string | undefined>>;

export interface Config {
  /** Which secret backend to load (`COATCHECK_PROVIDER`). */
  provider: string;
  /** Optional agent identity: logs, `{agentId}` in provider templates, STS session name. */
  agentId?: string;
  bindHost: string;
  port: number;
  ticketTtlSeconds: number;
  /** 0 disables the provider cache. */
  secretCacheTtlSeconds: number;
  ca: { dir?: string; subject: string };
  /** `vault_url` hint in 404s; omitted when unset. */
  missingSecretUrl?: string;
  /** Set when CDP injection is enabled. */
  cdp?: { port: number; advertiseHost: string };
  /** `COATCHECK_BROWSER_ADAPTERS`: built-in adapter names (custom adapters go through `startCoatcheck`). */
  browserAdapters: string[];
  /** From `COATCHECK_POLICY_FILE`; empty (no shared secrets, nothing bound) when unset. */
  policy: Policy;
  policyFile?: string;
  /** `COATCHECK_ALLOW_UNBOUND_SECRETS`: mint tickets for secrets with no allowed hosts (they swap for any host). */
  allowUnboundSecrets: boolean;
  mitm: MitmMode;
  /** `COATCHECK_PASSTHROUGH_HOSTS`: never MITM'd, in either mode (cert-pinned clients). */
  passthroughHosts: HostPattern[];
  /** `COATCHECK_API_TOKEN`: vault API bearer token and proxy credential. Required off loopback. */
  apiToken?: string;
}

/** Minimum `COATCHECK_API_TOKEN` length (e.g. `openssl rand -hex 32` gives 64). */
export const MIN_API_TOKEN_LENGTH = 32;

/** True for binds only reachable from the same host: 127.0.0.0/8, ::1, localhost. */
export function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '::1') return true;
  return net.isIPv4(h) && h.startsWith('127.');
}

/** Reads the policy file. Injected so `loadConfig` stays pure. */
export type ReadFile = (path: string) => string;

/** Built-in provider names; any other value is a module specifier (see load-provider.ts). */
export const KNOWN_PROVIDERS = ['aws', 'env', 'file'] as const;

/** Pre-1.0 names that now fail startup with a pointer to the new one. */
export const LEGACY_ENV_NAMES: Readonly<Record<string, string>> = {
  AGENT_LABEL: 'COATCHECK_AGENT_ID',
  PROXY_PORT: 'COATCHECK_PORT',
  PROXY_BIND_HOST: 'COATCHECK_BIND_HOST',
  CA_DIR: 'COATCHECK_CA_DIR',
  PROXY_ROLE_ARN: 'COATCHECK_AWS_ROLE_ARN',
  CDP_PROXY_ENABLED: 'COATCHECK_CDP_ENABLED',
  CDP_PROXY_PORT: 'COATCHECK_CDP_PORT',
  CDP_PROXY_ADVERTISE_HOST: 'COATCHECK_CDP_ADVERTISE_HOST',
};

const DEFAULT_CA_SUBJECT = 'CN=coatcheck CA, O=coatcheck';

export class ConfigError extends Error {
  constructor(readonly problems: string[]) {
    super(`Invalid configuration:\n${problems.map(p => `  - ${p}`).join('\n')}`);
    this.name = 'ConfigError';
  }
}

/** Collects problems while parsing so startup reports all of them, not just the first. */
export class EnvReader {
  readonly problems: string[] = [];

  constructor(private readonly env: Env) {}

  string(name: string): string | undefined {
    const v = this.env[name];
    return v === undefined || v === '' ? undefined : v;
  }

  int(name: string, def: number, min: number, max: number): number {
    const raw = this.string(name);
    if (raw === undefined) return def;
    if (!/^[0-9]+$/.test(raw) || Number(raw) < min || Number(raw) > max) {
      this.problems.push(`${name} must be an integer from ${min} to ${max} (got '${raw}')`);
      return def;
    }
    return Number(raw);
  }

  bool(name: string, def: boolean): boolean {
    const raw = this.string(name);
    if (raw === undefined) return def;
    if (raw === '1' || raw === 'true') return true;
    if (raw === '0' || raw === 'false') return false;
    this.problems.push(`${name} must be 1/0 or true/false (got '${raw}')`);
    return def;
  }
}

/**
 * Replace `{agentId}` in a template. Records a problem (and returns the
 * template unchanged) when the template needs an agent id that is unset.
 */
export function interpolateAgentId(template: string, agentId: string | undefined, name: string, problems: string[]): string {
  if (!template.includes('{agentId}')) return template;
  if (agentId === undefined) {
    problems.push(`${name} references {agentId} but COATCHECK_AGENT_ID is unset`);
    return template;
  }
  return template.split('{agentId}').join(agentId);
}

export function loadConfig(env: Env, readFile?: ReadFile): Config {
  const r = new EnvReader(env);

  for (const [legacy, current] of Object.entries(LEGACY_ENV_NAMES)) {
    if (env[legacy] !== undefined) r.problems.push(`${legacy} was renamed to ${current}`);
  }

  const provider = r.string('COATCHECK_PROVIDER');
  if (provider === undefined) {
    r.problems.push(`COATCHECK_PROVIDER is required (${KNOWN_PROVIDERS.join(', ')}, or a module specifier)`);
  }

  const agentId = r.string('COATCHECK_AGENT_ID');
  if (agentId !== undefined && !isValidSecretName(agentId)) {
    r.problems.push('COATCHECK_AGENT_ID must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ (it is interpolated into store paths)');
  }

  const missingSecretUrl = r.string('COATCHECK_MISSING_SECRET_URL');
  if (missingSecretUrl !== undefined && !/^https?:\/\//.test(missingSecretUrl)) {
    r.problems.push('COATCHECK_MISSING_SECRET_URL must be an http(s) URL');
  }

  const policyFile = r.string('COATCHECK_POLICY_FILE');
  let policy = EMPTY_POLICY;
  if (policyFile !== undefined) {
    let text: string | undefined;
    try {
      if (!readFile) throw new Error('no file reader available');
      text = readFile(policyFile);
    } catch (err) {
      r.problems.push(`COATCHECK_POLICY_FILE: cannot read '${policyFile}' (${(err as Error).message})`);
    }
    if (text !== undefined) policy = parsePolicy(text, r.problems, `COATCHECK_POLICY_FILE '${policyFile}'`);
  }

  const mitmRaw = r.string('COATCHECK_MITM') ?? 'bound';
  if (mitmRaw !== 'bound' && mitmRaw !== 'always') {
    r.problems.push(`COATCHECK_MITM must be 'bound' or 'always' (got '${mitmRaw}')`);
  }
  const passthroughHosts: HostPattern[] = [];
  for (const entry of (r.string('COATCHECK_PASSTHROUGH_HOSTS') ?? '').split(',').map(e => e.trim()).filter(Boolean)) {
    const p = entry.toLowerCase().startsWith('http://') ? 'must not have a scheme' : parseHostPattern(entry);
    if (typeof p === 'string') r.problems.push(`COATCHECK_PASSTHROUGH_HOSTS entry '${entry}': ${p}`);
    else passthroughHosts.push(p);
  }

  const bindHost = r.string('COATCHECK_BIND_HOST') ?? '127.0.0.1';
  const apiToken = r.string('COATCHECK_API_TOKEN');
  if (apiToken !== undefined && (apiToken.length < MIN_API_TOKEN_LENGTH || /\s/.test(apiToken))) {
    // Never echo the token itself.
    r.problems.push(`COATCHECK_API_TOKEN must be at least ${MIN_API_TOKEN_LENGTH} characters with no whitespace (e.g. openssl rand -hex 32)`);
  }
  if (apiToken === undefined && !isLoopbackHost(bindHost)) {
    r.problems.push(`COATCHECK_API_TOKEN is required when COATCHECK_BIND_HOST is not loopback (got '${bindHost}'): anything that can reach the port could mint tickets`);
  }

  const browserAdapters = (r.string('COATCHECK_BROWSER_ADAPTERS') ?? 'browserbase').split(',').map(e => e.trim()).filter(Boolean);
  const builtinAdapters = Object.keys(BUILTIN_BROWSER_ADAPTERS);
  for (const name of browserAdapters) {
    if (!builtinAdapters.includes(name)) {
      r.problems.push(`COATCHECK_BROWSER_ADAPTERS: unknown adapter '${name}' (built-ins: ${builtinAdapters.join(', ')}; custom adapters go through startCoatcheck)`);
    }
  }

  const cdpEnabled = r.bool('COATCHECK_CDP_ENABLED', false);
  const cdpPort = r.int('COATCHECK_CDP_PORT', 8444, 1, 65535);
  const config: Config = {
    provider: provider ?? '',
    agentId,
    bindHost,
    port: r.int('COATCHECK_PORT', 3128, 0, 65535),
    ticketTtlSeconds: r.int('COATCHECK_TICKET_TTL_SECONDS', 900, 1, 86_400),
    secretCacheTtlSeconds: r.int('COATCHECK_SECRET_CACHE_TTL_SECONDS', 300, 0, 86_400),
    ca: {
      dir: r.string('COATCHECK_CA_DIR'),
      subject: r.string('COATCHECK_CA_SUBJECT') ?? DEFAULT_CA_SUBJECT,
    },
    missingSecretUrl,
    cdp: cdpEnabled
      ? { port: cdpPort, advertiseHost: r.string('COATCHECK_CDP_ADVERTISE_HOST') ?? '127.0.0.1' }
      : undefined,
    browserAdapters,
    policy,
    policyFile,
    allowUnboundSecrets: r.bool('COATCHECK_ALLOW_UNBOUND_SECRETS', false),
    mitm: mitmRaw === 'always' ? 'always' : 'bound',
    passthroughHosts,
    apiToken,
  };

  if (r.problems.length > 0) throw new ConfigError(r.problems);
  return config;
}
