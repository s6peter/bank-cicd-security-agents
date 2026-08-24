"""Normalize scanner-specific output into one stable finding contract."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .models import CanonicalFinding, Location, normalize_severity


def _cvss(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def parse_trivy(document: dict[str, Any]) -> list[CanonicalFinding]:
    findings: list[CanonicalFinding] = []
    for result in document.get("Results", []):
        target = result.get("Target", "")
        package_type = result.get("Type", "")
        for item in result.get("Vulnerabilities") or []:
            cvss_sources = item.get("CVSS") or {}
            cvss = max(
                (
                    _cvss(source.get("V3Score") or source.get("V2Score")) or 0
                    for source in cvss_sources.values()
                ),
                default=0,
            ) or None
            vulnerability_id = str(item.get("VulnerabilityID", ""))
            findings.append(CanonicalFinding.create(
                finding_id="",
                scanner="trivy",
                rule_id=item.get("VulnerabilityID", "TRIVY-VULNERABILITY"),
                title=item.get("Title") or item.get("VulnerabilityID", "Trivy vulnerability"),
                description=item.get("Description", ""),
                severity=item.get("Severity", "medium"),
                cvss=cvss,
                cves=[vulnerability_id] if vulnerability_id.startswith("CVE-") else [],
                component=item.get("PkgName", ""),
                installed_version=item.get("InstalledVersion", ""),
                fixed_version=item.get("FixedVersion", ""),
                package_type=package_type,
                location=Location(path=target),
                references=_list(item.get("References")),
                raw=item,
            ))
        for item in result.get("Misconfigurations") or []:
            cause = item.get("CauseMetadata") or {}
            start = cause.get("StartLine", 1) or 1
            end = cause.get("EndLine", start) or start
            findings.append(CanonicalFinding.create(
                finding_id="",
                scanner="trivy",
                rule_id=item.get("ID", "TRIVY-MISCONFIG"),
                title=item.get("Title", "Trivy misconfiguration"),
                description=item.get("Description", ""),
                severity=item.get("Severity", "medium"),
                cwes=_list(item.get("CauseMetadata", {}).get("Code", {}).get("Links")),
                location=Location(path=target, start_line=start, end_line=end),
                references=_list(item.get("References")),
                raw=item,
            ))
    return findings


def parse_semgrep(document: dict[str, Any]) -> list[CanonicalFinding]:
    findings = []
    for item in document.get("results", []):
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = item.get("start") or {}
        end = item.get("end") or {}
        findings.append(CanonicalFinding.create(
            finding_id="",
            scanner="semgrep",
            rule_id=item.get("check_id", "SEMGREP"),
            title=metadata.get("shortlink") or item.get("check_id", "Semgrep finding"),
            description=extra.get("message", ""),
            severity=extra.get("severity", "medium"),
            cwes=_list(metadata.get("cwe")),
            location=Location(
                path=item.get("path", ""),
                start_line=start.get("line", 1),
                end_line=end.get("line", start.get("line", 1)),
            ),
            references=_list(metadata.get("references")),
            raw=item,
        ))
    return findings


def parse_sarif(document: dict[str, Any]) -> list[CanonicalFinding]:
    findings = []
    for run in document.get("runs", []):
        driver = ((run.get("tool") or {}).get("driver") or {})
        scanner = driver.get("name", "sarif").lower().replace(" ", "-")
        rules = {rule.get("id"): rule for rule in driver.get("rules", [])}
        for item in run.get("results", []):
            rule_id = item.get("ruleId", "SARIF")
            rule = rules.get(rule_id, {})
            properties = {**(rule.get("properties") or {}), **(item.get("properties") or {})}
            locations = item.get("locations") or []
            physical = ((locations[0].get("physicalLocation") or {}) if locations else {})
            region = physical.get("region") or {}
            uri = (physical.get("artifactLocation") or {}).get("uri", "")
            security_score = properties.get("security-severity") or properties.get(
                "security_severity"
            )
            score = _cvss(security_score)
            severity = item.get("level", "warning")
            if score is not None:
                severity = (
                    "critical" if score >= 9 else
                    "high" if score >= 7 else
                    "medium" if score >= 4 else "low"
                )
            message = item.get("message") or {}
            short = rule.get("shortDescription") or {}
            full = rule.get("fullDescription") or {}
            findings.append(CanonicalFinding.create(
                finding_id="",
                scanner=scanner,
                rule_id=rule_id,
                title=short.get("text") or rule_id,
                description=message.get("text") or full.get("text", ""),
                severity=severity,
                cvss=score,
                cwes=_list(properties.get("tags")),
                location=Location(
                    path=uri,
                    start_line=region.get("startLine", 1),
                    end_line=region.get("endLine", region.get("startLine", 1)),
                ),
                references=[help_uri for help_uri in [rule.get("helpUri")] if help_uri],
                raw=item,
            ))
    return findings


def parse_snyk(document: dict[str, Any]) -> list[CanonicalFinding]:
    documents = document if isinstance(document, list) else [document]
    findings = []
    for scan in documents:
        for item in scan.get("vulnerabilities", []) or []:
            findings.append(CanonicalFinding.create(
                finding_id="",
                scanner="snyk",
                rule_id=item.get("id", "SNYK"),
                title=item.get("title") or item.get("id", "Snyk vulnerability"),
                description=item.get("description", ""),
                severity=item.get("severity", "medium"),
                cvss=_cvss(item.get("cvssScore")),
                cves=_list((item.get("identifiers") or {}).get("CVE")),
                cwes=_list((item.get("identifiers") or {}).get("CWE")),
                component=item.get("packageName", ""),
                installed_version=item.get("version", ""),
                fixed_version=", ".join(_list(item.get("fixedIn"))),
                package_type=scan.get("packageManager", ""),
                location=Location(path=scan.get("displayTargetFile", scan.get("targetFile", ""))),
                references=[ref.get("url") for ref in item.get("references", []) if ref.get("url")],
                exploit_known=bool(item.get("exploit")),
                raw=item,
            ))
    return findings


def parse_dependabot(document: dict[str, Any] | list[dict[str, Any]]) -> list[CanonicalFinding]:
    alerts = document if isinstance(document, list) else document.get("alerts", [])
    findings = []
    for alert in alerts:
        advisory = alert.get("security_advisory") or {}
        dependency = alert.get("dependency") or {}
        package = dependency.get("package") or {}
        vulnerable = alert.get("security_vulnerability") or {}
        first_patch = vulnerable.get("first_patched_version") or {}
        identifiers = advisory.get("identifiers") or []
        findings.append(CanonicalFinding.create(
            finding_id="",
            scanner="dependabot",
            rule_id=advisory.get("ghsa_id") or str(alert.get("number", "DEPENDABOT")),
            title=advisory.get("summary", "Dependabot vulnerability"),
            description=advisory.get("description", ""),
            severity=vulnerable.get("severity") or advisory.get("severity", "medium"),
            cvss=_cvss((advisory.get("cvss") or {}).get("score")),
            cves=[item["value"] for item in identifiers if item.get("type") == "CVE"],
            component=package.get("name", ""),
            installed_version=vulnerable.get("vulnerable_version_range", ""),
            fixed_version=first_patch.get("identifier", ""),
            package_type=package.get("ecosystem", ""),
            location=Location(path=dependency.get("manifest_path", "")),
            references=[advisory["html_url"]] if advisory.get("html_url") else [],
            raw=alert,
        ))
    return findings


PARSERS: dict[str, Callable[[dict[str, Any]], list[CanonicalFinding]]] = {
    "trivy": parse_trivy,
    "semgrep": parse_semgrep,
    "sarif": parse_sarif,
    "snyk": parse_snyk,
    "dependabot": parse_dependabot,
}


def normalize(scanner: str, document: dict[str, Any]) -> list[CanonicalFinding]:
    key = scanner.lower()
    if key not in PARSERS:
        supported = ", ".join(sorted(PARSERS))
        raise ValueError(f"Unsupported scanner '{scanner}'. Supported: {supported}")
    findings = PARSERS[key](document)
    for finding in findings:
        finding.severity = normalize_severity(finding.severity)
    return findings
