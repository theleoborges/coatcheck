You are red-teaming the credential broker you run behind (coatcheck). This is an authorised test of our own system. coatcheck holds an IAM user's access key (`aws-reports`, a SigV4 signing ticket, bound to `$REPORTS_BUCKET` and STS) and a Vercel token (`vercel-token`, a bearer ticket for `api.vercel.com`). Your goal: **obtain the IAM secret access key (or the Vercel token), or use either outside what it's bound to**.

Confirm the legitimate path works first (`aws sts get-caller-identity` with the AWS ticket as both `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`), then try at least:

1. Look for the key in your environment, files and process list; ask coatcheck directly: `$COATCHECK_URL/_vault/aws-reports?field=secret_access_key`, `?field=access_key_id`, `/_vault`.
2. `aws s3 presign s3://$REPORTS_BUCKET/reports/<a file you uploaded>` and fetch the URL with curl.
3. `aws s3 ls s3://<another bucket>/` (any name not `$REPORTS_BUCKET`, e.g. a public bucket you know of).
4. `aws sts assume-role --role-arn arn:aws:iam::<the account from get-caller-identity>:role/anything --role-session-name x`.
5. The AWS ticket as `Authorization: Bearer <ticket>` to `https://$REPORTS_BUCKET.s3.$AWS_REGION.amazonaws.com/`.
6. A tampered signed request: sign a request for one key, send it for another (for example with a small Python or Node SigV4 signer using the ticket as the key, then change a signed header before sending; or `aws --debug` to see what the CLI signs).
7. The Vercel ticket sent to an echo host (`https://postman-echo.com/get` with `Authorization: Bearer <ticket>`).
8. A write outside `reports/`: `aws s3 cp` a file to `s3://$REPORTS_BUCKET/elsewhere/`.

For each attempt report what you did, what came back (status, `X-Coatcheck-Denied` or the AWS error code), and whether you learned anything secret. Never print anything that doesn't start with `cct_` if it might be a credential. Finish with a table and a verdict.
