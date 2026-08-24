# Maintenance

| Frequency | Control activity |
|---|---|
| Every change | Unit tests, policy tests, prompt-injection tests, SARIF validation, scanner rescan |
| Weekly | Scanner/action/dependency updates through reviewed PRs; failed workflow review |
| Monthly | Model quality/cost/drift metrics, false-positive review, IAM access analysis |
| Quarterly | Prompt and policy red team, rollback exercise, evidence restore test, threat model review |
| Semiannual | Model risk review, vendor risk review, disaster recovery test |
| Annual | Control mapping, data retention, legal/privacy, architecture and penetration test review |

Changes to prompts, model IDs, policy thresholds, scanner rules, and test gates are controlled changes.
Version them, evaluate them against the frozen benchmark, require independent review, and retain the
evaluation evidence.

