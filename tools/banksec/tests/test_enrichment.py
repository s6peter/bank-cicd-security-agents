from datetime import date

from banksec_agents.enrichment import enrich_findings
from banksec_agents.models import CanonicalFinding, Location


def test_eol_and_kev_enrichment():
    finding = CanonicalFinding.create(
        finding_id="finding-123456",
        scanner="test",
        rule_id="TEST",
        title="test",
        description="test",
        severity="medium",
        cves=["CVE-2024-0001"],
        component="python",
        installed_version="3.8.19",
        location=Location(path="requirements.txt"),
    )
    stats = enrich_findings(
        [finding],
        eol_catalog={"python": [{"cycle": "3.8", "eol": "2024-10-07"}]},
        product_map={"python": "python"},
        kev_catalog={"vulnerabilities": [{"cveID": "CVE-2024-0001"}]},
        as_of=date(2025, 1, 1),
    )
    assert finding.end_of_life
    assert finding.exploit_known
    assert stats == {"eol_matches": 1, "kev_matches": 1}
