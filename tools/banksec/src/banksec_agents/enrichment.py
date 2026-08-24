"""Apply versioned, offline threat-intelligence catalogs to canonical findings."""

from __future__ import annotations

from datetime import date
from typing import Any

from .models import CanonicalFinding


def enrich_findings(
    findings: list[CanonicalFinding],
    eol_catalog: dict[str, list[dict[str, Any]]] | None = None,
    product_map: dict[str, str] | None = None,
    kev_catalog: dict[str, Any] | None = None,
    as_of: date | None = None,
) -> dict[str, int]:
    """Mutate findings with EOL and known-exploited evidence from local snapshots."""
    as_of = as_of or date.today()
    eol_catalog = eol_catalog or {}
    product_map = product_map or {}
    known_exploited = {
        item.get("cveID")
        for item in (kev_catalog or {}).get("vulnerabilities", [])
        if item.get("cveID")
    }
    stats = {"eol_matches": 0, "kev_matches": 0}
    for finding in findings:
        if known_exploited.intersection(finding.cves):
            finding.exploit_known = True
            stats["kev_matches"] += 1

        product = product_map.get(finding.component)
        if not product or not finding.installed_version:
            continue
        release = _matching_cycle(eol_catalog.get(product, []), finding.installed_version)
        if release and _is_eol(release.get("eol"), as_of):
            finding.end_of_life = True
            stats["eol_matches"] += 1
    return stats


def _matching_cycle(cycles: list[dict[str, Any]], version: str) -> dict[str, Any] | None:
    normalized = version.strip().lstrip("v")
    matches = [
        cycle
        for cycle in cycles
        if normalized == str(cycle.get("cycle", ""))
        or normalized.startswith(f"{cycle.get('cycle')}.")
    ]
    return max(matches, key=lambda item: len(str(item.get("cycle", ""))), default=None)


def _is_eol(value: Any, as_of: date) -> bool:
    if value is True:
        return True
    if not value:
        return False
    try:
        return date.fromisoformat(str(value)) <= as_of
    except ValueError:
        return False

