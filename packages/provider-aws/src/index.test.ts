import { describe, it, expect } from 'vitest';
import { awsErrorCode, loadAwsConfig } from './index.js';
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
