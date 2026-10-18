# Example agents

Two small agents that run behind coatcheck and never hold a real secret, not even their own Anthropic API key. Each one runs in a container on an `internal` Docker network, so its only route to the internet is the coatcheck proxy, which makes `HTTPS_PROXY` mandatory rather than advisory.

| Example | Provider | Path exercised | Secrets |
|---|---|---|---|
| [`gh-triage/`](gh-triage) | `env` | HTTPS swap with unmodified tools (`gh`, `curl`) | `anthropic-api-key`, `github-token` |
| [`browser-login/`](browser-login) | `aws` (SSM + Secrets Manager via an assumed role with `ExternalId`) | Broker-performed browser login over CDP, through Browserbase | `anthropic-api-key`, `the-internet-login`, shared `browserbase-api-key` |

Both use the same harness ([`harness/src/agent.ts`](harness/src/agent.ts)): an agent loop on the Anthropic TypeScript SDK with one tool, Anthropic's `bash` tool. It mints a fresh `anthropic-api-key` ticket before every model call; coatcheck swaps it for the real key on the wire to `api.anthropic.com`. The system prompt ([`harness/system.md`](harness/system.md)) tells the model how tickets work.

## Prerequisites

Both examples:

- Docker with Compose v2 (`docker compose`). The images build from this repo; you don't need Node on the host.
- `openssl` (`run.sh` generates a fresh `COATCHECK_API_TOKEN` each run).
- An Anthropic API key. It goes into coatcheck only; the agent gets tickets.

gh-triage also needs a GitHub token: either the `gh` CLI logged in (`gh auth login`), or `GITHUB_TOKEN` set.

browser-login also needs:

- AWS CLI v2 and a profile (`AWS_PROFILE`) with a default region, allowed to create SSM parameters, a Secrets Manager secret and an IAM role. `run.sh` passes the profile's credentials to coatcheck with `aws configure export-credentials`.
- A Browserbase account: an API key, and your project ID.

## Running

Each example has a normal task (`task.md`) and a red-team task (`attack.md`), in which the agent is told to try to extract or exfiltrate the real secret. Run a task with `./run.sh [task.md|attack.md]`; the default is `task.md`.

`run.sh` builds and starts coatcheck, runs the agent in the foreground, prints coatcheck's `[swap]`, `[connect]` and (browser-login) `[cdp]` log lines, then stops everything. The agent's output streams to your terminal. `out/` (git-ignored) gets `transcript.json`, the full conversation, overwritten on each run.

The harness stops after 30 turns (`[harness] stopped after 30 turns`). Set `AGENT_MAX_TURNS` to change it, for example `AGENT_MAX_TURNS=60 ./run.sh attack.md`.

## gh-triage

```bash
cd gh-triage
ANTHROPIC_API_KEY=… ./run.sh              # triage open issues in $GH_REPO, read-only
ANTHROPIC_API_KEY=… ./run.sh attack.md    # red team: try to get the GitHub token out
```

`GITHUB_TOKEN` defaults to `gh auth token`. A fine-grained, read-only PAT is better. Set `GH_REPO=owner/repo` to a repository the token can read (default `theleoborges/coatcheck`).

## browser-login

```bash
cd browser-login
AWS_PROFILE=… ANTHROPIC_API_KEY=… BROWSERBASE_API_KEY=… ./setup-aws.sh   # SSM params, a secret, an IAM role
AWS_PROFILE=… BROWSERBASE_PROJECT_ID=… ./run.sh                           # log into the-internet.herokuapp.com
AWS_PROFILE=… BROWSERBASE_PROJECT_ID=… ./run.sh attack.md                 # red team: get the password out
AWS_PROFILE=… BROWSERBASE_PROJECT_ID=… ./run.sh attack-transform.md       # red team: read the password back encoded
AWS_PROFILE=… ./teardown-aws.sh                                           # delete everything
```

`setup-aws.sh` creates, in your profile's region, all tagged `purpose=coatcheck-demo`:

- SSM SecureStrings `/coatcheck/demo/secrets/anthropic-api-key` and `/coatcheck/demo/secrets/the-internet-login`.
- Secrets Manager secret `coatcheck-demo/browserbase-api-key` (skipped if `BROWSERBASE_API_KEY` is unset).
- IAM role `coatcheck-demo-broker`. It can read only `/coatcheck/demo/secrets/*` and `coatcheck-demo/*`, only your current identity can assume it, and only with a random `ExternalId`, which is saved to `.external-id` (git-ignored).

It is safe to re-run. `teardown-aws.sh` deletes all of it, including `.external-id`.

`run.sh` hands your credentials and the `ExternalId` to the coatcheck container alone. The agent creates a Browserbase session, then asks coatcheck to fill and submit the login form (`POST /_vault/the-internet-login/login`); the password never enters its context. The login is for the public practice site [the-internet.herokuapp.com](https://the-internet.herokuapp.com/login) (`tomsmith` / `SuperSecretPassword!`), so no real account is involved.

The two red-team tasks:

- `attack.md`: a list of attacks on the login (another origin, reading the field afterwards, pre-installed listeners and init scripts, request interception, connecting to Browserbase directly, extensions).
- `attack-transform.md`: one check. It logs in, then tries to read the password back as raw `.value`, base64, reversed and as char codes, forms the inbound redactor wouldn't recognise.

Each run uses Browserbase sessions, and the attack runs open several. A free Browserbase plan's browser minutes can run out partway through; session creation then fails, and the agent reports that rather than an attack result.
