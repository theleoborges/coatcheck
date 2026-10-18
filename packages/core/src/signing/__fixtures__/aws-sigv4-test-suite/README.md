# AWS SigV4 test-suite vectors

Published AWS Signature Version 4 test-suite cases, copied unchanged from
[awslabs/aws-c-auth](https://github.com/awslabs/aws-c-auth/tree/84a26ea184d9ccd322c8164759510b3604ab13fd/tests/aws-signing-test-suite/v4)
at commit `84a26ea184d9ccd322c8164759510b3604ab13fd` (Apache-2.0; `LICENSE`
and `NOTICE` in this directory). Credentials `AKIDEXAMPLE` /
`wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, `2015-08-30T12:36:00Z`,
`us-east-1`, service `service` (see each `context.json`).

Per case: `header-signed-request.txt` (the signed request), and the expected
`header-canonical-request.txt`, `header-string-to-sign.txt` and
`header-signature.txt`. Used by `../sigv4.test.ts`. Nothing here was derived.
