"""Export normalized and enriched findings to GitHub-supported SARIF 2.1.0."""

from __future__ import annotations

from typing import Any

from .models import CanonicalFinding, RiskAssessment

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(
    findings: list[CanonicalFinding],
    assessments: dict[str, RiskAssessment] | None = None,
) -> dict[str, Any]:
    assessments = assessments or {}
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in findings:
        rules.setdefault(finding.rule_id, {
            "id": finding.rule_id,
            "name": finding.title[:120],
            "shortDescription": {"text": finding.title[:1024]},
            "fullDescription": {"text": (finding.description or finding.title)[:4096]},
            "helpUri": finding.references[0] if finding.references else None,
            "properties": {
                "tags": finding.cwes + finding.cves,
                **({"security-severity": str(finding.cvss)} if finding.cvss is not None else {}),
            },
        })
        rule = rules[finding.rule_id]
        if rule["helpUri"] is None:
            rule.pop("helpUri")
        assessment = assessments.get(finding.finding_id)
        properties: dict[str, Any] = {
            "banksecFindingId": finding.finding_id,
            "scanner": finding.scanner,
        }
        if assessment:
            properties.update({
                "banksecRiskScore": assessment.score,
                "banksecRiskBand": assessment.band.value,
                "banksecDisposition": assessment.disposition.value,
            })
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": LEVEL[finding.severity.value],
            "message": {"text": finding.description or finding.title},
            "properties": properties,
        }
        if finding.location.path:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location.path},
                    "region": {
                        "startLine": max(1, finding.location.start_line),
                        "endLine": max(finding.location.start_line, finding.location.end_line),
                    },
                }
            }]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "BankSec Remediation Agents",
                "informationUri": "https://github.com/strands-agents/sdk-python",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
