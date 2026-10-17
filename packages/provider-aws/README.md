# @coatcheck/provider-aws

coatcheck secret provider for AWS (`COATCHECK_PROVIDER=aws`): per-agent secrets in SSM Parameter Store, shared secrets in Secrets Manager, optionally read through an assumed role. This is the only coatcheck package that depends on the AWS SDK.

Settings (`COATCHECK_AWS_SSM_PREFIX`, `COATCHECK_AWS_SHARED_PREFIX`, `COATCHECK_AWS_ROLE_ARN`, `COATCHECK_AWS_EXTERNAL_ID`, `COATCHECK_AWS_ROLE_SESSION_NAME`) and the backend layout are documented in the [main README](../../README.md#secret-backend-layout-aws). Read [docs/THREAT_MODEL.md](../../docs/THREAT_MODEL.md) before deploying: a broker role the agent can also assume protects nothing. [docs/deploy/aws-ecs.md](../../docs/deploy/aws-ecs.md) is the reference ECS deployment (sidecar with `COATCHECK_AWS_EXTERNAL_ID`, or a separate task).
