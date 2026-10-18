# @coatcheck/core

The coatcheck broker: HTTPS MITM proxy, vault API, tickets, CA, and CDP proxy, plus the `coatcheck` bin. Secret backends are separate packages loaded at startup by `COATCHECK_PROVIDER` (`@coatcheck/provider-env`, `@coatcheck/provider-aws`, or your own module). See the [main README](https://github.com/theleoborges/coatcheck#readme).

```bash
npm install -g @coatcheck/core @coatcheck/provider-env   # the `coatcheck` bin + the env and file providers
COATCHECK_PROVIDER=env COATCHECK_SECRET_EXAMPLE_API_KEY=… coatcheck
```

Embedding:

```ts
import { loadConfig, startCoatcheck, createMemoryProvider } from '@coatcheck/core';

const running = await startCoatcheck({
  config: loadConfig({ COATCHECK_PROVIDER: 'memory', COATCHECK_PORT: '0' }),
  provider: createMemoryProvider({ secrets: { 'github-token': 'ghp_…' } }),
});
// running.port, running.tokenStore, … ; await running.close();
```
