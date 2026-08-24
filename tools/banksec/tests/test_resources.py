from importlib.resources import files
from pathlib import Path


def test_auditable_policy_copy_matches_packaged_policy():
    root = Path(__file__).resolve().parents[1]
    visible = (root / "policies" / "remediation-policy.json").read_text(encoding="utf-8")
    packaged = files("banksec_agents").joinpath(
        "resources", "policies", "remediation-policy.json"
    ).read_text(encoding="utf-8")
    assert visible == packaged


def test_auditable_prompt_copies_match_packaged_prompts():
    root = Path(__file__).resolve().parents[1]
    for visible_path in (root / "prompts").glob("*.md"):
        packaged = files("banksec_agents").joinpath(
            "resources", "prompts", visible_path.name
        ).read_text(encoding="utf-8")
        assert visible_path.read_text(encoding="utf-8") == packaged
