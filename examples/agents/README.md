# Example agents

Two small agents that run behind coatcheck and never hold a real secret, not even their own Anthropic API key. Each one runs in a container on an `internal` Docker network, so its only route to the internet is the coatcheck proxy, which makes `HTTPS_PROXY` mandatory rather than advisory.

| Example | Provider | Path exercised | Secrets |
|---|---|---|---|
| [`gh-triage/`](gh-triage) | `env` | HTTPS swap with unmodified tools (`gh`, `curl`) | `anthropic-api-key`, `github-token` |
| [`browser-login/`](browser-login) | `aws` (SSM + Secrets Manager via an assumed role with `ExternalId`) | CDP credential injection through Browserbase | `anthropic-api-key`, `the-internet-login`, shared `browserbase-api-key` |

Both use the same harness ([`harness/src/agent.ts`](harness/src/agent.ts)): an agent loop on the Anthropic TypeScript SDK with one tool, Anthropic's `bash` tool. It mints a fresh `anthropic-api-key` ticket before every model call; coatcheck swaps it for the real key on the wire to `api.anthropic.com`. The system prompt ([`harness/system.md`](harness/system.md)) tells the model how tickets work.

Each example has a normal task (`task.md`) and a red-team task (`attack.md`), in which the agent is told to try to extract or exfiltrate the real secret. Run a task with `./run.sh [task.md|attack.md]`. Transcripts land in `out/`, and the run ends by printing coatcheck's `[swap]`, `[connect]` and `[cdp]` log lines.

## gh-triage

```bash
cd gh-triage
ANTHROPIC_API_KEY=… ./run.sh              # triage open issues in $GH_REPO (default theleoborges/coatcheck), read-only
ANTHROPIC_API_KEY=… ./run.sh attack.md    # red team: try to get the GitHub token out
```

`GITHUB_TOKEN` defaults to `gh auth token`. A fine-grained, read-only PAT is better.

## browser-login

```bash
cd browser-login
AWS_PROFILE=… ANTHROPIC_API_KEY=… BROWSERBASE_API_KEY=… ./setup-aws.sh   # SSM params, a secret, an IAM role
AWS_PROFILE=… BROWSERBASE_PROJECT_ID=… ./run.sh                           # log into the-internet.herokuapp.com
AWS_PROFILE=… BROWSERBASE_PROJECT_ID=… ./run.sh attack.md                 # red team: get the password out
AWS_PROFILE=… ./teardown-aws.sh                                           # delete everything
```

`setup-aws.sh` creates the `coatcheck-demo-broker` role. It can read only `/coatcheck/demo/secrets/*` and `coatcheck-demo/*`, and only your current identity can assume it, and only with a random `ExternalId`. `run.sh` hands your credentials and the `ExternalId` to the coatcheck container alone. The login is for the public practice site [the-internet.herokuapp.com](https://the-internet.herokuapp.com/login) (`tomsmith` / `SuperSecretPassword!`), so no real account is involved.
