# Deploying coatcheck on AWS ECS

This is the reference deployment for the `aws` provider: per-agent secrets in
SSM Parameter Store, shared secrets in Secrets Manager, and coatcheck running
next to the agent on ECS (Fargate or EC2). Read
[THREAT_MODEL.md](../THREAT_MODEL.md) first. The point of the layout below is
property 2 there: **the agent's own AWS identity can't read the secrets**,
only coatcheck's can.

Values in angle brackets and the account `123456789012` / region `us-east-1`
are placeholders. AWS-hosted agents should use a scoped task role for their own AWS access; coatcheck's SigV4 signing ([signing-processors.md](../design/signing-processors.md)) is for keys that can't be roles (agents off AWS, S3-compatible stores, a counterparty's IAM user key). Use the published image,
`ghcr.io/theleoborges/coatcheck:<version>` (public), or build your own from
this repo's `Dockerfile`. Either way, keeping a copy in your own ECR repository
(for example through an ECR pull-through cache rule for `ghcr.io`) means tasks
don't depend on GHCR at launch. It is based on `node:24-slim` (coatcheck needs
Node 24), runs as the `node` user (UID 1000), listens on `3128` (proxy and
vault API) and, with CDP enabled, `8444`.

## Choose a shape

| | A. Sidecar + `ExternalId` | B. Separate task |
|---|---|---|
| Where coatcheck runs | a second container in the agent's task | its own ECS service |
| How the agent reaches it | `127.0.0.1:3128` (shared network namespace) | the service's private address, with `COATCHECK_API_TOKEN` |
| AWS identity | shared task role; coatcheck assumes a **broker role** with an `ExternalId` only its container holds | coatcheck's own task role; no role to assume |
| Egress enforcement | weak on Fargate (one ENI, one security group for both containers) | security groups: the agent may only reach coatcheck |
| CA lifetime | per task | per coatcheck task; agents re-fetch `/_ca` when it restarts |

**B is the stronger option**, because ECS gives each task its own role and its
own security group, and coatcheck doesn't have to rely on a shared secret.
**A is simpler to run** (one task per agent, no service discovery) and is safe
for secrets as long as the `ExternalId` stays out of the agent container.
Both are covered below.

### The pitfall both shapes avoid

All containers in one ECS task share **one task role**. If coatcheck runs as a
sidecar and assumes a broker role whose trust policy only names the task role,
the agent container can call `sts:AssumeRole` on the broker role too (its SDK
picks up the same credentials from `169.254.170.2`) and read every secret
directly. An explicit deny on the task role doesn't help: the assumed broker
role is a different principal. coatcheck logs a startup warning when
`COATCHECK_AWS_ROLE_ARN` is set without `COATCHECK_AWS_EXTERNAL_ID` for this
reason.

## IAM

### Agent task role (shape A: shared with the sidecar)

The agent's identity gets an **explicit deny** on the secret stores, so that a
broader policy attached later (for example an `*:Get*` managed policy) can't
open them up:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenySecretStores",
      "Effect": "Deny",
      "Action": [
        "ssm:GetParameter", "ssm:GetParameters",
        "ssm:PutParameter", "secretsmanager:GetSecretValue"
      ],
      "Resource": [
        "arn:aws:ssm:us-east-1:123456789012:parameter/coatcheck/secrets/*",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:coatcheck/*",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:coatcheck-infra/*"
      ]
    },
    {
      "Sid": "DenyParameterPathReads",
      "Effect": "Deny",
      "Action": ["ssm:GetParametersByPath"],
      "Resource": "*"
    },
    {
      "Sid": "DenyExecIntoTheSidecar",
      "Effect": "Deny",
      "Action": ["ecs:ExecuteCommand"],
      "Resource": "*"
    },
    {
      "Sid": "SidecarAssumesBroker",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::123456789012:role/coatcheck-broker-<agent-id>"
    }
  ]
}
```

- `coatcheck-infra/*` holds the `ExternalId` (below). Denying it here means
  the agent can't fetch it with the task role.
- `ssm:GetParametersByPath` is denied everywhere, not just under the prefix.
  A recursive read of a parent path (`/coatcheck`, or `/`) returns the
  parameters below it even when they are denied by name. coatcheck makes
  that call with the broker's identity, never the task role's.
- The `sts:AssumeRole` allow is what the sidecar needs. The agent has it too,
  which is why the broker's trust policy also demands the `ExternalId`.
- In shape B this role belongs to the agent alone. Keep the deny statements
  and drop `SidecarAssumesBroker`.

### Broker role (shape A)

One per agent, so an agent's coatcheck can only read that agent's prefix.
Permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:PutParameter"],
      "Resource": "arn:aws:ssm:us-east-1:123456789012:parameter/coatcheck/secrets/<agent-id>/*"
    },
    {
      "Effect": "Allow",
      "Action": "ssm:GetParametersByPath",
      "Resource": "arn:aws:ssm:us-east-1:123456789012:parameter/coatcheck/secrets/<agent-id>"
    },
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:coatcheck/browserbase-api-key-*"
      ]
    }
  ]
}
```

Add `kms:Decrypt` on the key if the parameters or secrets use a customer
managed KMS key. `ssm:PutParameter` is only needed for OAuth refresh, which
writes rotated tokens back. `ssm:GetParametersByPath` is checked against the
path itself (no trailing `/*`); coatcheck uses it to list secret names
(`GET /_vault`). The Secrets Manager entry lists each shared secret by name;
the `-*` covers the random suffix AWS adds to secret ARNs.

Trust policy: the task role may assume it **only with the `ExternalId`**:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::123456789012:role/agent-task-<agent-id>" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "<external-id>" } }
  }]
}
```

Generate the `ExternalId` like a password (`openssl rand -hex 32`) and store it
in Secrets Manager as `coatcheck-infra/<agent-id>/external-id`. To rotate it,
update the trust policy and the secret together, then restart the tasks.

### Execution role (shape A)

ECS uses the **execution role**, not the task role, to fetch container-level
`secrets`. That is how the `ExternalId` reaches the coatcheck container and no
other: the execution role's credentials are never exposed inside the task.

```json
{
  "Effect": "Allow",
  "Action": "secretsmanager:GetSecretValue",
  "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:coatcheck-infra/<agent-id>/external-id-*"
}
```

plus the usual ECR pull and CloudWatch Logs permissions.

### coatcheck task role (shape B)

In shape B coatcheck has its own task, so its task role *is* the broker: give
it the broker permissions above and leave `COATCHECK_AWS_ROLE_ARN` unset. No
`ExternalId` is needed, because the agent never holds this role's
credentials. If one coatcheck service serves several agents, scope its
permissions to all of their prefixes and set `COATCHECK_AWS_SSM_PREFIX`
per deployment; for per-agent isolation run one coatcheck service per agent.

## Task definition (shape A)

```json
{
  "family": "agent-<agent-id>",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "taskRoleArn": "arn:aws:iam::123456789012:role/agent-task-<agent-id>",
  "executionRoleArn": "arn:aws:iam::123456789012:role/agent-exec-<agent-id>",
  "containerDefinitions": [
    {
      "name": "coatcheck",
      "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/coatcheck:<tag>",
      "essential": true,
      "user": "node",
      "readonlyRootFilesystem": true,
      "environment": [
        { "name": "COATCHECK_PROVIDER", "value": "aws" },
        { "name": "COATCHECK_AGENT_ID", "value": "<agent-id>" },
        { "name": "COATCHECK_AWS_SSM_PREFIX", "value": "/coatcheck/secrets/{agentId}/" },
        { "name": "COATCHECK_AWS_ROLE_ARN", "value": "arn:aws:iam::123456789012:role/coatcheck-broker-<agent-id>" },
        { "name": "COATCHECK_POLICY_FILE", "value": "/etc/coatcheck/policy.json" },
        { "name": "AWS_REGION", "value": "us-east-1" }
      ],
      "secrets": [
        {
          "name": "COATCHECK_AWS_EXTERNAL_ID",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:coatcheck-infra/<agent-id>/external-id"
        }
      ],
      "healthCheck": {
        "command": ["CMD", "node", "-e", "fetch('http://127.0.0.1:3128/_health').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"],
        "interval": 5,
        "timeout": 3,
        "retries": 3,
        "startPeriod": 5
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/coatcheck",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "<agent-id>"
        }
      }
    },
    {
      "name": "agent",
      "image": "<your agent image>",
      "essential": true,
      "dependsOn": [{ "containerName": "coatcheck", "condition": "HEALTHY" }],
      "entryPoint": ["/usr/local/bin/coatcheck-entrypoint.sh"],
      "command": ["<your agent command>"],
      "environment": [
        { "name": "HTTPS_PROXY", "value": "http://127.0.0.1:3128" },
        { "name": "HTTP_PROXY", "value": "http://127.0.0.1:3128" },
        { "name": "NO_PROXY", "value": "localhost,127.0.0.1,169.254.169.254,169.254.170.2" },
        { "name": "COATCHECK_URL", "value": "http://127.0.0.1:3128" }
      ]
    }
  ]
}
```

Notes:

- **The `ExternalId` is in `secrets`, not `environment`.** Anything in
  `environment` is readable by whoever can call `ecs:DescribeTaskDefinition`
  or `ecs:DescribeTasks`, which may include the agent. A `secrets` entry only
  shows its ARN, and its value is injected into the coatcheck container only.
- **Health-gated startup.** ECS ignores the image's Dockerfile `HEALTHCHECK`,
  so the task definition repeats it. `dependsOn … HEALTHY` holds the agent
  back until `/_health` answers, so the agent never starts without a broker
  or a CA to trust. The image has no `curl`; the check uses Node's `fetch`.
- **Both containers are `essential`.** If coatcheck exits, ECS stops the
  task instead of leaving the agent running unbrokered.
- **Leave `pidMode` unset.** With `"pidMode": "task"` the agent could read the
  coatcheck process's environment (`/proc/<pid>/environ`), including the
  `ExternalId`.
- **Don't enable ECS Exec** on these services. Exec into the coatcheck
  container reads its environment. The task role above also denies
  `ecs:ExecuteCommand`.
- **Policy file.** Every secret needs allowed hosts, from the policy or from
  an `_allowed_hosts` key in the secret's JSON, or coatcheck refuses to mint a
  ticket for it (403). Shared secrets (`/_secret/*`) must be listed
  under `shared`:

  ```json
  {
    "secrets": {
      "example-api-key": { "allowed_hosts": ["api.example.com"] }
    },
    "shared": {
      "browserbase-api-key": { "allowed_hosts": ["api.browserbase.com"] }
    }
  }
  ```

  Fargate has no host bind mounts, so bake the policy into a thin image of
  your own:

  ```dockerfile
  FROM 123456789012.dkr.ecr.us-east-1.amazonaws.com/coatcheck:<tag>
  COPY policy.json /etc/coatcheck/policy.json
  ```

- **Bind address.** The sidecar keeps the default `127.0.0.1`, which the agent
  reaches through the shared network namespace. Nothing outside the task can
  connect, so `COATCHECK_API_TOKEN` is optional here.
- **Browser logins (CDP).** Add `COATCHECK_CDP_ENABLED=1`. Browserbase
  session responses are rewritten so the agent connects to
  `ws://127.0.0.1:8444/cdp/…`, and the agent asks coatcheck to fill and
  submit a login form with `POST /_vault/{name}/login`. The login secret is a
  multi-field JSON parameter (`{"username":…,"password":…}`) in the agent's
  SSM prefix, and its allowed hosts are the login page's origin. In shape B,
  also set `COATCHECK_CDP_ADVERTISE_HOST` to the address the agent uses for
  coatcheck.

## CA trust in the agent entrypoint

coatcheck's default CA is generated in memory when it starts, so the agent
fetches it at startup. `dependsOn … HEALTHY` guarantees it is there, but the
entrypoint still waits, so it also works under plain Docker:

```sh
#!/bin/sh
# /usr/local/bin/coatcheck-entrypoint.sh (in the agent image)
set -eu
CC="${COATCHECK_URL:-http://127.0.0.1:3128}"

for i in $(seq 1 30); do
  curl -sf --noproxy '*' "$CC/_health" >/dev/null && break
  sleep 1
done
curl -sf --noproxy '*' "$CC/_ca" -o /tmp/coatcheck-ca.crt

export NODE_EXTRA_CA_CERTS=/tmp/coatcheck-ca.crt           # Node
cat /etc/ssl/certs/ca-certificates.crt /tmp/coatcheck-ca.crt > /tmp/ca-bundle.crt
export SSL_CERT_FILE=/tmp/ca-bundle.crt                     # OpenSSL-based tools, Go
export REQUESTS_CA_BUNDLE=/tmp/ca-bundle.crt                # Python requests
export CURL_CA_BUNDLE=/tmp/ca-bundle.crt                    # curl
export GIT_SSL_CAINFO=/tmp/ca-bundle.crt                    # git

# If the agent needs no AWS credentials of its own, drop the pointers to the
# credentials endpoint (defence in depth only; see "Blocking 169.254.170.2").
exec env -u AWS_CONTAINER_CREDENTIALS_RELATIVE_URI \
         -u AWS_CONTAINER_CREDENTIALS_FULL_URI \
         -u AWS_CONTAINER_AUTHORIZATION_TOKEN \
         "$@"
```

The bundle is built in `/tmp` rather than with `update-ca-certificates`, so
the agent can run as a non-root user with a read-only root filesystem.
Tools with their own trust store (Java keystores, some language runtimes) need
their own step; see [clients.md](../clients.md).

## Blocking 169.254.170.2

`169.254.170.2` is the ECS container credentials endpoint: it hands the task
role's credentials to any process in the task that knows the task's
credentials path. Blocking the agent from it removes the shared-task-role
problem at the root, if the agent doesn't need AWS credentials of its own.

- **EC2 launch type:** run the agent and coatcheck under different UIDs and
  add an init container with `NET_ADMIN` that rejects the endpoint for every
  UID except coatcheck's (`node`, 1000 in the image):

  ```sh
  iptables -A OUTPUT -d 169.254.170.2 -m owner ! --uid-owner 1000 -j REJECT
  ```

  The containers share the task's network namespace, so the rule applies to
  the agent too. Also block the instance metadata service
  (`ECS_AWSVPC_BLOCK_IMDS=true` in the ECS agent config, or an IMDSv2 hop
  limit of 1), or the agent can take the instance role instead.
- **Fargate:** containers can't get `NET_ADMIN`, so there is no per-container
  network block. Removing `AWS_CONTAINER_CREDENTIALS_*` from the agent's
  environment (the entrypoint above) hides the credentials path, but it is not
  a boundary on its own. Rely on the `ExternalId` (shape A) or a separate task
  (shape B).

## Egress rules

`HTTPS_PROXY` is advisory: a process that ignores it bypasses coatcheck. It
then gets no substitution, so it still can't use a secret, but it can reach
any host directly. Enforce egress below the agent:

- **Shape B:** give the agent task a security group whose egress allows only
  the coatcheck service's security group on `3128` (and `8444` for CDP), plus
  DNS and any VPC endpoints the agent needs. coatcheck's security group allows
  ingress from the agent's group only, and egress `443` to the internet (or
  to a NAT gateway or AWS Network Firewall with a domain allowlist). Set
  `COATCHECK_BIND_HOST=0.0.0.0` and `COATCHECK_API_TOKEN` on coatcheck; the
  agent sends the token as its proxy password
  (`HTTPS_PROXY=http://coatcheck:<token>@<coatcheck address>:3128`) and as
  `Authorization: Bearer` on the vault API.
- **Shape A:** both containers share one ENI and one security group, so a
  security group can't tell them apart. On EC2, add an `owner`-match rule like
  the one above that lets only coatcheck's UID leave the task. On Fargate, the
  best available control is a VPC-level allowlist (AWS Network Firewall)
  limiting what the whole task can reach; the agent can still reach the hosts
  coatcheck can.
- Keep `COATCHECK_MITM=bound` (the default) unless you need the broker to see
  every connection.

## CA key handling

- **Default: ephemeral.** With `COATCHECK_CA_DIR` unset, the CA key exists
  only in the coatcheck process's memory and dies with the task. Every task has
  its own CA, so a CA leaked from one task can't intercept another agent's
  traffic. This is the recommended setting for ECS.
- **Persisted** (`COATCHECK_CA_DIR`): only if agents must trust a CA that is
  fixed in advance. Mount the directory into the coatcheck container only, and
  never on storage that agent tasks can mount (an EFS file system shared with
  agents hands every agent the key to intercept every other agent's TLS). The
  directory holds the private key with mode `0600`; nothing else should be on
  that volume.
- Leaf certificates are never written to disk.
- On a restart (shape B), a new ephemeral CA means agents get TLS errors until
  they re-fetch `/_ca`. Restart the agents with coatcheck, or persist the CA as
  above.

## Verifying a deployment

From inside the agent container:

```sh
# Property 2: the agent's identity can't read the secrets...
aws ssm get-parameter --with-decryption --name /coatcheck/secrets/<agent-id>/example-api-key   # AccessDenied
aws secretsmanager get-secret-value --secret-id coatcheck/browserbase-api-key              # AccessDenied
# ...or become the broker without the ExternalId.
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/coatcheck-broker-<agent-id> \
  --role-session-name probe                                                                 # AccessDenied
aws secretsmanager get-secret-value --secret-id coatcheck-infra/<agent-id>/external-id     # AccessDenied

# The broker works: mint a ticket and use it at an allowed host.
# (Shape B: add -H "Authorization: Bearer $COATCHECK_API_TOKEN" to the first curl.)
TICKET=$(curl -s "$COATCHECK_URL/_vault/example-api-key" | sed 's/.*"token":"\([^"]*\)".*/\1/')
curl -s -H "Authorization: Bearer $TICKET" https://<allowed host>/…                       # real value swapped in
# A host bound to a different secret refuses it (403 host-mismatch).
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TICKET" https://<host bound to another secret>/   # 403
```

A host no secret is bound to (`https://example.org/`, say) is tunnelled
untouched in the default `COATCHECK_MITM=bound` mode: it answers normally, and
all it receives is the literal `cct_…` ticket.

In coatcheck's logs, look for `[swap] … result=hit` and no `WARNING:
COATCHECK_AWS_ROLE_ARN is set without COATCHECK_AWS_EXTERNAL_ID` line.
