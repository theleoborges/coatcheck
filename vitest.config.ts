import { defineConfig } from 'vitest/config';

// One project per workspace package. `@coatcheck/source` resolves workspace
// imports (`@coatcheck/core`) to TypeScript source, so tests need no build.
export default defineConfig({
  resolve: { conditions: ['@coatcheck/source'] },
  test: {
    projects: ['core', 'provider-aws', 'provider-env'].map(name => ({
      extends: true,
      test: { name, root: `packages/${name}`, include: ['src/**/*.test.ts'] },
    })),
  },
});
