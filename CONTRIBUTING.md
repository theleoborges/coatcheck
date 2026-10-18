# Contributing

Thanks for looking. Before you start on anything non-trivial, open an issue so we can agree on the shape; [`docs/ROADMAP.md`](docs/ROADMAP.md) and [`docs/design/`](docs/design) record what has been decided and why.

**Found a vulnerability?** Don't open an issue. See [SECURITY.md](SECURITY.md).

## Setup

Node ≥ 24.

```bash
npm install
npx playwright install chromium                                    # once, for the CDP e2e test
npm run lint && npm run type-check && npm test && npm run build
COATCHECK_PROVIDER=env COATCHECK_SECRET_DEMO=x npm run dev        # runs the TypeScript source
```

The package layout and the role of each file are in the [README](README.md#development) and [`CLAUDE.md`](CLAUDE.md).

## Pull requests

- CI runs lint, type-check, the tests (including the Chromium e2e), the build, and the Docker build on Node 24 and 26. All of it has to pass.
- Tests are colocated (`*.test.ts`, vitest). New behaviour comes with tests.
- **Security-relevant changes need a test that performs the attack and shows it blocked.** `packages/core/src/server.test.ts` and `packages/core/src/cdp/e2e.test.ts` have examples. If a change moves a line in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), update the threat model in the same PR.
- Never log secret values, ticket IDs, or request bodies: only secret names, counts, and ages.
- Only `packages/core/src/config.ts` and `cli.ts` read `process.env`; providers get their environment through `ProviderContext`.
- Core must not depend on a provider package. Providers peer-depend on `@coatcheck/core`.
- Move files with `git mv` so history follows them.

## Releases

Maintainers:

1. `npm version X.Y.Z --workspaces --no-git-tag-version` (all three packages move together), open a PR, merge.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`. [`release.yml`](.github/workflows/release.yml) runs the checks and **stages** each package on npm with provenance, via a stage-only trusted publisher. Nothing is live yet.
3. Review and approve each staged version with 2FA, core first (the providers peer-depend on it): `npx npm@latest stage list`, then `npx npm@latest stage approve <id>` — or the Staged Packages tab on npmjs.com.
4. Publish the release notes on GitHub Releases.

Tokens can't publish `@coatcheck/*` (publishing access is "require 2FA and disallow tokens"); a release always ends with a maintainer's approval.
