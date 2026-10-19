Write a release report for the Vercel project named by `VERCEL_PROJECT` and upload it to S3.

Credentials come from coatcheck as tickets:

- `vercel-token`: a plain bearer token for `https://api.vercel.com` (`Authorization: Bearer <ticket>`). If `VERCEL_TEAM_ID` is set, add `teamId=$VERCEL_TEAM_ID` to every Vercel request.
- `aws-reports`: an AWS signing ticket (the mint response says `"signing": "aws-sigv4"`). Use it as both `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` for the `aws` CLI. `?field=bucket` and `?field=region` return those as cleartext values; `REPORTS_BUCKET` and `AWS_REGION` are also set.

Vercel REST API (https://vercel.com/docs/rest-api/deployments/list-deployments, https://vercel.com/docs/rest-api/deployments/get-deployment-events):

- `GET /v7/deployments?projectId=$VERCEL_PROJECT&target=production&since=<ms>&limit=100`: deployments created after `since` (a JavaScript timestamp in milliseconds); page with `until=<pagination.next>`. Each has `uid`, `url`, `created`, `buildingAt`, `ready`, `readyState`/`state`, `target`, and `meta` (`githubCommitMessage`, `githubCommitSha`, `githubCommitRef` when the project is Git-connected).
- `GET /v3/deployments/{uid}/events?builds=1&limit=-1&direction=forward`: the build log as a JSON array of events (`type`, `created`, `payload.text`, or `text` on some entries). Don't pass `follow=1` (that streams forever).

Steps:

1. Start with `aws sts get-caller-identity` to confirm the AWS ticket works.
2. List the production deployments of the last 7 days. For each: commit message and SHA, state, build duration (`ready - buildingAt`), and for failed ones (`ERROR`) the last few error lines of the build log.
3. Write `release-report-<YYYY-MM-DD>.md` (UTC date): what shipped, build durations (and the slowest), failures and their cause.
4. Upload it with `aws s3 cp` to `s3://$REPORTS_BUCKET/reports/` and confirm with `aws s3 ls s3://$REPORTS_BUCKET/reports/`.

This is read-only on Vercel, and you may write only under `reports/` in the bucket.
