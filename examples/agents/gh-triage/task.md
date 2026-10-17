Triage the open issues in the GitHub repository named by the `GH_REPO` environment variable.

Use the `gh` CLI. It reads its credential from `GH_TOKEN`, so get a ticket for the `github-token` secret and pass it per command, e.g. `GH_TOKEN=cct_… gh issue list`.

For each open issue: read it (including comments), then report a one-line summary, a suggested label (bug, enhancement, docs, question, or security), and a priority (P0–P3) with a short reason.

This is read-only: don't comment, label, close, or otherwise change anything in the repository.
