# Architecture

## Trust boundaries

```text
Untrusted PR checkout                         Trusted default-branch workflow
+---------------------------+                +--------------------------------+
| scanners, tests, build    |--artifacts---->| policy + evidence validation   |
| no AWS credentials        |                | protected GitHub environment   |
| contents:read             |                +---------------+----------------+
+---------------------------+                                |
                                                             | GitHub OIDC
                                                             v
                                              +-------------------------------+
                                              | AWS role: Bedrock invoke only |
                                              +---------------+---------------+
                                                              |
                                                              v
                                              +-------------------------------+
                                              | Strands specialist agents     |
                                              | no shell/GitHub/file tools    |
                                              +---------------+---------------+
                                                              |
                                                        patch proposal
                                                              v
                                              +-------------------------------+
                                              | deterministic path, size,     |
                                              | exact-match, test gates       |
                                              +---------------+---------------+
                                                              |
                                                        review-only PR
```

## Agent responsibilities

| Agent | Input | Output | Explicitly cannot do |
|---|---|---|---|
| Finding Interpreter | Canonical finding, fixed risk score, source window | Evidence and uncertainty | Set score or disposition |
| Patch Engineer | Finding, interpretation, exact source | Exact replacement proposal | Read other files or execute tools |
| Patch Reviewer | Proposal, source, finding | Independent approve/reject opinion | Override policy or tests |
| Evidence Reporter | Recorded outcomes | Technical and executive summary | Invent passing tests or approvals |

## Why this is a deterministic workflow

Strands supports dynamic swarms and graphs, but remediation is a poor place for unconstrained routing.
This project uses fixed specialist stages around code-owned gates. The model handles ambiguous language
and code reasoning; ordinary Python handles authority, paths, risk bands, limits, and evidence.

## Production data stores

Replace local artifacts with services owned by the bank:

| Local POC | Production pattern |
|---|---|
| `audit.jsonl` | CloudWatch Logs plus S3 Object Lock or approved immutable evidence store |
| local policy JSON | Signed, versioned policy artifact from a protected repository |
| workflow artifacts | Retention-controlled evidence bucket and case-management link |
| local model settings | Approved model registry/configuration service |
| GitHub token | Dedicated GitHub App with repository allowlist and minimal permissions |

