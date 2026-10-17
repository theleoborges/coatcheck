import { describe, it, expect } from 'vitest';
import { awsErrorCode } from './aws.js';

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
