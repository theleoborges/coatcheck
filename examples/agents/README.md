# Example agents

Small agents that run behind coatcheck and never hold a real secret, not even their own Anthropic API key. Each one runs in a container on an `internal` Docker network, so its only route to the internet is the coatcheck proxy, which makes `HTTPS_PROXY` mandatory rather than advisory.

| Example | Provider | Path exercised | Secrets |
|---|---|---|---|
| [`gh-triage/`](gh-triage) | `env` | HTTPS swap with unmodified tools (`gh`, `curl`) | `anthropic-api-key`, `github-token` |
| [`browser-login/`](browser-login) | `aws` (SSM + Secrets Manager via an assumed role with `ExternalId`) | Broker-performed browser login over CDP, through Browserbase | `anthropic-api-key`, `the-internet-login`, shared `browserbase-api-key` |
| [`vercel-release-report/`](vercel-release-report) | `env` | A bearer swap (Vercel) and AWS SigV4 re-signing (unmodified `aws` CLI, IAM user key) from an agent off AWS | `anthropic-api-key`, `vercel-token`, `aws-reports` (signing) |

All use the same harness ([`harness/src/agent.ts`](harness/src/agent.ts)): an agent loop on the Anthropic TypeScript SDK with one tool, Anthropic's `bash` tool. It mints a fresh `anthropic-api-key` ticket before every model call; coatcheck swaps it for the real key on the wire to `api.anthropic.com`. The system prompt ([`harness/system.md`](harness/system.md)) tells the model how tickets work.

## Prerequisites

All examples:

- Docker with Compose v2 (`docker compose`). The images build from this repo; you don't need Node on the host.
- `openssl` (`run.sh` generates a fresh `COATCHECK_API_TOKEN` each run).
- An Anthropic API key. It goes into coatcheck only; the agent gets tickets.

gh-triage also needs a GitHub token: either the `gh` CLI logged in (`gh auth login`), or `GITHUB_TOKEN` set.

browser-login also needs:

- AWS CLI v2 and a profile (`AWS_PROFILE`) with a default region, allowed to create SSM parameters, a Secrets Manager secret and an IAM role. `run.sh` passes the profile's credentials to coatcheck with `aws configure export-credentials`.
- A Browserbase account: an API key, and your project ID.

vercel-release-report also needs:

- AWS CLI v2 and a profile (`AWS_PROFILE`) with a default region, allowed to create an S3 bucket, an IAM user and its access key. Only `setup-aws.sh` and `teardown-aws.sh` use the profile.
- `jq` on the host (the scripts read `.aws-reporter-key` with it).
- A Vercel token and a project name or id (`VERCEL_PROJECT`); `VERCEL_TEAM_ID` for a team project.

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

## vercel-release-report

An agent that is **not on AWS** reads a Vercel project and writes a report to S3. One policy shows both kinds of ticket side by side: `vercel-token` is a plain bearer swap, `aws-reports` is a SigV4 **signing ticket** (the unmodified `aws` CLI signs with the ticket; coatcheck verifies and re-signs with the IAM user's real key, which never leaves coatcheck). See [Signed requests](../../README.md#signed-requests).

```bash
cd vercel-release-report
AWS_PROFILE=… ./setup-aws.sh                                                      # bucket, IAM user, one access key
ANTHROPIC_API_KEY=… VERCEL_TOKEN=… VERCEL_PROJECT=… ./run.sh                     # report for the last 7 days → s3://…/reports/
ANTHROPIC_API_KEY=… VERCEL_TOKEN=… VERCEL_PROJECT=… ./run.sh attack.md           # red team: get the IAM key out or use it elsewhere
VERCEL_TOKEN=… VERCEL_PROJECT=… ./smoke.sh                                        # no model: the same commands, then the negative checks
AWS_PROFILE=… ./teardown-aws.sh                                                   # delete everything
```

Set `VERCEL_TEAM_ID` for a project under a team. Create the token at [vercel.com/account/tokens](https://vercel.com/account/tokens). **Vercel tokens are account-wide**: host binding keeps the token on `api.vercel.com`, it doesn't limit what the token can do there. Use a token scoped to the team you need, and keep the run read-only as the task says.

`setup-aws.sh` creates, in your profile's region, all tagged `purpose=coatcheck-demo`:

- S3 bucket `coatcheck-demo-reports-<account-id>` (public access blocked, default encryption).
- IAM user `coatcheck-demo-reporter` with one inline policy: `s3:PutObject`/`s3:GetObject` on `reports/*` and `s3:ListBucket` on the `reports/` prefix, nothing else.
- One access key for it, saved to `.aws-reporter-key` (git-ignored, mode 0600) with the bucket and region.

It is safe to re-run (an existing key file is kept). To rotate, delete `.aws-reporter-key` and re-run: the user's old keys are deleted before the new one is created. `teardown-aws.sh` deletes the key, the user, the bucket's objects and the bucket, and `.aws-reporter-key`.

`run.sh` and `smoke.sh` need no AWS profile: they pass the reporter key to the coatcheck container only (`COATCHECK_SECRET_AWS_REPORTS`, env provider) and render `policy.json` from `policy.template.json` (`<bucket>.s3.<region>.amazonaws.com` and `sts.<region>.amazonaws.com`, `signing: aws-sigv4`). The agent image is built with the AWS CLI (`INSTALL_AWS_CLI=1`). `COATCHECK_MITM=always` makes coatcheck intercept every tunnel, so a request to another bucket is refused by coatcheck (`403 host-mismatch`) instead of reaching S3 as a literal.

What the run exercises: `aws sts get-caller-identity` (a form POST with no payload-hash header: the body is buffered, hashed and re-signed), `aws s3 cp` (the CLI sends `x-amz-content-sha256`, so the upload streams), `aws s3 ls`. Presigned URLs don't work: the ticket in `X-Amz-Credential` leaves as a literal and S3 answers `InvalidAccessKeyId`. Authorisation stays with IAM: a write outside `reports/` is IAM's `AccessDenied`.

`smoke.sh` runs `sts get-caller-identity`, `s3 cp` of a generated file, `s3 ls`, and one Vercel `GET /v7/deployments` in the agent container, then the negative checks (another bucket: `403`; a presigned URL: `403 InvalidAccessKeyId`), and asserts coatcheck's `result=signed`, `result=denied`, `result=placement-skipped` and the `vercel-token` hit. It leaves one small object under `reports/smoke/`.
