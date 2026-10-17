import { describe, it, expect, vi } from 'vitest';
import createProvider, { assumeRoleInput, awsConfigWarnings, awsErrorCode, loadAwsConfig } from './index.js';
import { ConfigError } from '@coatcheck/core';

describe('awsErrorCode', () => {
  it('reads the code from err.name', () => {
    const err = new Error('nope');
    err.name = 'ParameterNotFound';
    expect(awsErrorCode(err)).toBe('ParameterNotFound');
  });

  it('falls back to err.Code when name is generic', () => {
    const err = Object.assign(new Error('nope'), { Code: 'ResourceNotFoundException' });
    expect(awsErrorCode(err)).toBe('ResourceNotFoundException');
    expect(awsErrorCode({ Code: 'ResourceNotFoundException' })).toBe('ResourceNotFoundException');
  });

  it('returns empty for unknown shapes', () => {
    expect(awsErrorCode(new Error('x'))).toBe('');
    expect(awsErrorCode(null)).toBe('');
    expect(awsErrorCode('boom')).toBe('');
  });
});

describe('loadAwsConfig', () => {
  const load = (env: Record<string, string>, agentId?: string) => loadAwsConfig({ env, agentId });

  it('defaults to coatcheck prefixes and no role', () => {
    expect(load({})).toEqual({
      ssmPrefix: '/coatcheck/secrets/',
      sharedPrefix: 'coatcheck/',
      roleArn: undefined,
      roleSessionName: 'coatcheck',
    });
    expect(load({}, 'agent-7').roleSessionName).toBe('coatcheck-agent-7');
  });

  it('interpolates {agentId} into prefixes and the session name', () => {
    expect(load({
      COATCHECK_AWS_SSM_PREFIX: '/acme/agents/{agentId}/secrets/',
      COATCHECK_AWS_SHARED_PREFIX: 'acme/{agentId}/',
      COATCHECK_AWS_ROLE_SESSION_NAME: 'broker-{agentId}',
      COATCHECK_AWS_ROLE_ARN: 'arn:aws:iam::123456789012:role/coatcheck-broker',
    }, 'agent-7')).toEqual({
      ssmPrefix: '/acme/agents/agent-7/secrets/',
      sharedPrefix: 'acme/agent-7/',
      roleArn: 'arn:aws:iam::123456789012:role/coatcheck-broker',
      roleSessionName: 'broker-agent-7',
    });
  });

  it('fails when a template needs {agentId} and it is unset', () => {
    expect(() => load({ COATCHECK_AWS_SSM_PREFIX: '/acme/{agentId}/' })).toThrow(/references \{agentId\} but COATCHECK_AGENT_ID is unset/);
  });

  it('rejects malformed prefixes, session names and role ARNs', () => {
    for (const env of <Array<Record<string, string>>>[
      { COATCHECK_AWS_SSM_PREFIX: 'no-leading-slash/' },
      { COATCHECK_AWS_SSM_PREFIX: '/no-trailing-slash' },
      { COATCHECK_AWS_SSM_PREFIX: '/a//b/' },
      { COATCHECK_AWS_SHARED_PREFIX: 'bad prefix ' },
      { COATCHECK_AWS_ROLE_SESSION_NAME: 'x' },
      { COATCHECK_AWS_ROLE_ARN: 'not-an-arn' },
    ]) {
      expect(() => load(env), JSON.stringify(env)).toThrow(ConfigError);
    }
  });
});

describe('COATCHECK_AWS_EXTERNAL_ID', () => {
  const ROLE = 'arn:aws:iam::123456789012:role/coatcheck-broker';
  const load = (env: Record<string, string>) => loadAwsConfig({ env });

  it('is sent as sts:ExternalId when assuming the broker role', () => {
    const config = load({ COATCHECK_AWS_ROLE_ARN: ROLE, COATCHECK_AWS_EXTERNAL_ID: 'ext-0123456789abcdef' });
    expect(assumeRoleInput({ ...config, roleArn: ROLE })).toEqual({
      RoleArn: ROLE, RoleSessionName: 'coatcheck', DurationSeconds: 3600, ExternalId: 'ext-0123456789abcdef',
    });
    expect(assumeRoleInput({ ...load({ COATCHECK_AWS_ROLE_ARN: ROLE }), roleArn: ROLE })).not.toHaveProperty('ExternalId');
  });

  it('warns at startup when a role is assumed without it (the shared-task-role pitfall)', async () => {
    expect(awsConfigWarnings(load({ COATCHECK_AWS_ROLE_ARN: ROLE }))).toEqual([expect.stringContaining('without COATCHECK_AWS_EXTERNAL_ID')]);
    expect(awsConfigWarnings(load({ COATCHECK_AWS_ROLE_ARN: ROLE, COATCHECK_AWS_EXTERNAL_ID: 'ext-1' }))).toEqual([]);
    expect(awsConfigWarnings(load({}))).toEqual([]);

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      await createProvider({ env: { COATCHECK_AWS_ROLE_ARN: ROLE } });
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('can assume the broker role itself'));
      warn.mockClear();
      await createProvider({ env: { COATCHECK_AWS_ROLE_ARN: ROLE, COATCHECK_AWS_EXTERNAL_ID: 'ext-1' } });
      expect(warn).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  it('rejects a malformed value without echoing it, and a value with no role to assume', () => {
    expect(() => load({ COATCHECK_AWS_ROLE_ARN: ROLE, COATCHECK_AWS_EXTERNAL_ID: 'has space secret-value' }))
      .toThrow(/COATCHECK_AWS_EXTERNAL_ID must be/);
    try {
      load({ COATCHECK_AWS_ROLE_ARN: ROLE, COATCHECK_AWS_EXTERNAL_ID: 'has space secret-value' });
    } catch (err) {
      expect(String((err as Error).message)).not.toContain('secret-value');
    }
    expect(() => load({ COATCHECK_AWS_EXTERNAL_ID: 'ext-1' })).toThrow(/COATCHECK_AWS_ROLE_ARN is not/);
  });
});
