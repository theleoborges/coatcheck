import { describe, it, expect } from 'vitest';
import { startCoatcheck } from './start.js';
import { loadConfig } from './config.js';
import { createMemoryProvider } from './memory-provider.js';

describe('startCoatcheck', () => {
  it('listens, serves the vault API from the provider, and closes everything', async () => {
    let closed = false;
    const provider = { ...createMemoryProvider({ secrets: { a: 'x', b: 'y' } }), close: async () => { closed = true; } };
    const config = loadConfig({ COATCHECK_PROVIDER: 'memory', COATCHECK_PORT: '0', COATCHECK_CDP_ENABLED: '1', COATCHECK_CDP_PORT: '1' });
    config.cdp = { port: 0, advertiseHost: '127.0.0.1' };
    const running = await startCoatcheck({ config, provider });
    try {
      expect(running.port).toBeGreaterThan(0);
      expect(running.cdp?.port).toBeGreaterThan(0);
      const res = await fetch(`http://127.0.0.1:${running.port}/_vault`);
      expect(await res.json()).toEqual({ secrets: ['a', 'b'] });
    } finally {
      await running.close();
    }
    expect(closed).toBe(true);
    await expect(fetch(`http://127.0.0.1:${running.port}/_health`)).rejects.toThrow();
  });
});
