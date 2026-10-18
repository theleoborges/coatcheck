# @coatcheck/provider-env

coatcheck secret providers with no cloud dependency. Both ship in the coatcheck Docker image. See the [main README](https://github.com/theleoborges/coatcheck#readme).

```bash
npm install -g @coatcheck/core @coatcheck/provider-env
COATCHECK_PROVIDER=env COATCHECK_SECRET_EXAMPLE_API_KEY=… coatcheck
```

## `env` (`COATCHECK_PROVIDER=env`)

Secrets come from environment variables, read once at startup. The provider is read-only, so `POST /_vault/{name}/refresh` returns `501`.

**Names are restricted to `[a-z0-9-]+`** (lowercase letters, digits, `-`) so the mapping is reversible: uppercase the name and replace `-` with `_`.

| Secret name | Variable |
|---|---|
| `github-token` | `COATCHECK_SECRET_GITHUB_TOKEN` |
| shared `browserbase-api-key` | `COATCHECK_SHARED_SECRET_BROWSERBASE_API_KEY` |

- Any other name gets `400` from the vault API (it could not be mapped back when listing).
- `GET /_vault` lists the variables under the prefix whose names map back; others are ignored.
- An empty variable counts as absent.
- `COATCHECK_ENV_PREFIX` (default `COATCHECK_SECRET_`) changes the prefix for named secrets. It must be an uppercase variable-name prefix that does not overlap `COATCHECK_SHARED_SECRET_`.

## `file` (`COATCHECK_PROVIDER=file`, module `@coatcheck/provider-env/file`)

Secrets come from the JSON file at `COATCHECK_SECRETS_FILE`:

```json
{
  "secrets": { "github-token": "ghp_…", "example-login": "{\"username\":\"u\",\"password\":\"p\"}" },
  "shared":  { "browserbase-api-key": "bb_…" }
}
```

- Values are strings; a multi-value secret is a JSON-encoded object. Unknown top-level keys fail startup.
- Names follow coatcheck's core rules (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).
- The file is re-read on each lookup (coatcheck caches lookups for `COATCHECK_SECRET_CACHE_TTL_SECONDS`), so edits apply without a restart.
- `put` (OAuth refresh) writes a temp file in the same directory with mode `0600` and renames it over the original, so a crash never leaves a truncated file. Writes within one process are serialised. The directory must be writable by coatcheck.
