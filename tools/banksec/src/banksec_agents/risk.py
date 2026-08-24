"""Deterministic risk scoring; the model may explain but cannot set this score."""

from __future__ import annotations

from .models import CanonicalFinding, RiskAssessment, Severity

SEVERITY_BASE = {
    Severity.INFO: 5,
    Severity.LOW: 20,
    Severity.MEDIUM: 40,
    Severity.HIGH: 70,
    Severity.CRITICAL: 90,
}


def score_finding(finding: CanonicalFinding) -> RiskAssessment:
    reasons: list[str] = []
    if finding.cvss is not None:
        score = round(max(0, min(10, finding.cvss)) * 10)
        reasons.append(f"CVSS {finding.cvss:.1f} contributes {score} points")
    else:
        score = SEVERITY_BASE[finding.severity]
        reasons.append(f"Scanner severity {finding.severity.value} starts at {score}")

    modifiers = [
        (finding.exploit_known, 10, "known exploit evidence"),
        (finding.reachable is True, 8, "vulnerable code is reachable"),
        (finding.production_exposed, 7, "production exposure"),
        (finding.sensitive_data_path, 8, "sensitive-data path"),
        (finding.end_of_life, 10, "end-of-life component"),
        (bool(finding.fixed_version), -5, "vendor fix is available"),
    ]
    for applies, points, reason in modifiers:
        if applies:
            score += points
            reasons.append(f"{reason}: {points:+d}")

    if finding.reachable is False:
        score -= 8
        reasons.append("reachability analysis found no execution path: -8")

    score = max(0, min(100, score))
    band = (
        Severity.CRITICAL if score >= 90 else
        Severity.HIGH if score >= 70 else
        Severity.MEDIUM if score >= 40 else
        Severity.LOW if score >= 10 else Severity.INFO
    )
    return RiskAssessment(finding_id=finding.finding_id, score=score, band=band, reasons=reasons)

