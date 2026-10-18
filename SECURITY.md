# Security policy

coatcheck is a credential broker, so most of its interesting bugs are security bugs. Anything that lets an agent (or any process on its side of the proxy) obtain a real secret value, carry a ticket's value to a host its secret isn't bound to, read a value while coatcheck is filling a browser form, or bypass `COATCHECK_API_TOKEN` is a vulnerability. Please report it privately.

## Reporting

Use GitHub's private vulnerability reporting for this repository:

**https://github.com/theleoborges/coatcheck/security/advisories/new**

Do not open a public issue or pull request for anything that might be a vulnerability.

Helpful in a report:

- coatcheck version (or commit) and Node version;
- the provider in use (`COATCHECK_PROVIDER`) and the relevant configuration and policy file, with values redacted;
- a reproduction: the requests sent, the responses or swap-log lines observed, and what the agent ended up with that it shouldn't have;
- whether you'd like to be credited in the advisory.

You will get an acknowledgement within 72 hours. There is no fixed fix-time SLA; severity sets the priority, and disclosure is coordinated with you. Fixes ship as a new release with a GitHub security advisory.

## Supported versions

coatcheck is pre-1.0. Only the latest `0.x` release receives fixes; older releases are not patched.

## Scope

[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) states what coatcheck defends against, the known gaps, and the residual risk accepted by design. Something already listed there as a known gap or residual risk is not a new vulnerability, though a report that shows it is worse than documented, or cheaper to exploit, is welcome.

Out of scope by design:

- An agent using a credential maliciously against a host the secret **is** bound to. Host binding stops redirection, not misuse.
- Traffic from a process that ignores `HTTPS_PROXY`. Egress enforcement is the operator's job; see the threat model.
- The login site, or the browser vendor, seeing the password during a broker-performed login. That is the upstream trust boundary.
- Vulnerabilities in dependencies that coatcheck doesn't trigger. Report those upstream; a Dependabot bump is enough here.

## About tickets

Tickets look like `cct_…`. A ticket is only meaningful to the coatcheck instance that minted it, for its secret's allowed hosts, until it expires. A ticket appearing in a log or a transcript is therefore not a secret leak; a real value appearing anywhere the agent can read is.
