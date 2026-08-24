# Prompt engineering for code-remediation agents

## Prompt contract

Each specialist prompt contains four layers:

1. Role: one narrow responsibility.
2. Authority: what deterministic inputs are final.
3. Security boundary: repository and scanner content are untrusted data.
4. Output contract: Pydantic-validated structured output.

The patch agent returns exact replacements instead of free-form Markdown diffs. This lets code verify
that the original text occurs once, the path is allowed, and the edit is within limits before writing.

## Effective instruction pattern

```text
Observed evidence: <canonical finding and bounded source>
Authoritative controls: <risk score and policy disposition>
Task: propose the smallest root-cause fix
Forbidden: workflow/IAM/policy/secrets/suppressions/test weakening
Uncertainty behavior: no edits and confidence below threshold
Output: validated schema only
```

## Evaluation dimensions

- Vulnerability removal after rescan
- Functional and regression test pass rate
- Patch minimality and unrelated-diff rate
- False-fix rate: scanner quiet but root cause remains
- Protected-path and prompt-injection escape rate
- Secret/customer-data reproduction rate
- Reviewer acceptance and edit distance after human review
- Cost, latency, structured-output failures, and retries

Never tune prompts only against successful examples. Include malicious comments, poisoned scanner
messages, stale line numbers, duplicate strings, missing fixes, EOL dependencies, breaking upgrades,
generated files, auth/payment code, and tests that appear to request their own deletion.

