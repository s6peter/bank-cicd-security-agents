# Infrastructure boundary

`cloudformation/github-bedrock-role.yaml` creates one GitHub OIDC role with model-invocation
permissions. It does not create the GitHub OIDC provider, Bedrock model access, an AgentCore runtime,
or any repository settings.

Deploy only after cloud security approval:

```bash
aws cloudformation deploy \
  --stack-name banksec-github-bedrock-role \
  --template-file infra/cloudformation/github-bedrock-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    GitHubOidcProviderArn=arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com \
    GitHubOrganization=YOUR_ORG \
    GitHubRepository=YOUR_REPO
```

Store the output role ARN in the GitHub organization or repository variable
`BANKSEC_BEDROCK_ROLE_ARN`. Restrict the model ARN parameter to the bank-approved inference profile.
