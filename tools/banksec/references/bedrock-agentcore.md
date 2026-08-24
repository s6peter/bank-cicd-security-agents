# Amazon Bedrock and AgentCore

## Direct Bedrock mode

The GitHub remediation workflow runs Strands inside the runner and calls Bedrock through a short-lived
OIDC role. This is the simplest MVP: source context stays inside the runner and only bounded text is
sent to the approved model.

Required actions are `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream` on approved model
or inference-profile ARNs. The model gets no AWS tools, shell, filesystem, GitHub token, or network tool.

## AgentCore mode

Use AgentCore when a central platform team operates the agents for many repositories and needs runtime
identity, versioned deployments, centralized observability, controlled ingress, or A2A/MCP integration.
The included AgentCore endpoint is read-only and does not apply patches. CI remains the authority for
repository changes.

Production additions:

- Private or policy-controlled network egress and approved ingress authentication
- AgentCore Gateway authorization and interceptors where applicable
- Bedrock Guardrails for prompt attacks, sensitive information, denied topics, and output filtering
- CloudWatch traces/metrics with source-content redaction and approved retention
- Immutable runtime versions, canary rollout, rollback, and online/offline evaluations
- Customer-managed encryption keys where required by the bank's data classification
- Separate development, test, and production AWS accounts and roles
- Service control policies and least-privilege customer-managed policies

Bedrock Automated Reasoning can validate agent claims against formalized policy, but it is detect-mode
feedback and does not replace application enforcement. Keep the Python policy gate authoritative.

## Deployment commands

```bash
python deploy.py configure
python deploy.py launch
python deploy.py invoke fixtures/trivy.json
python deploy.py teardown --delete-ecr-repo
```

`configure` is local. `launch` creates or updates AWS resources and can incur charges. Record the AWS
account, Region, runtime ARN, execution role, ECR repository, build project, logs, and teardown owner in
the change ticket before launch.

