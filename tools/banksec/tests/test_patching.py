from pathlib import Path

import pytest

from banksec_agents.models import Edit, PatchProposal
from banksec_agents.patching import ControlledPatchApplier, PatchRejected


def proposal(path="requirements.txt", original="demo==1.0\n", replacement="demo==1.1\n"):
    return PatchProposal(
        finding_id="finding-123456",
        summary="upgrade dependency",
        confidence=0.95,
        edits=[
            Edit(
                path=path,
                original=original,
                replacement=replacement,
                rationale="fixed release",
            )
        ],
        tests=["pytest"],
    )


def test_applies_exact_edit(tmp_path: Path):
    target = tmp_path / "requirements.txt"
    target.write_text("demo==1.0\n", encoding="utf-8")
    changed = ControlledPatchApplier(tmp_path).apply(proposal(), dry_run=False)
    assert changed == ["requirements.txt"]
    assert target.read_text(encoding="utf-8") == "demo==1.1\n"


def test_rejects_workflow_edit(tmp_path: Path):
    target = tmp_path / ".github" / "workflows" / "ci.yml"
    target.parent.mkdir(parents=True)
    target.write_text("permissions: {}\n", encoding="utf-8")
    with pytest.raises(PatchRejected, match="forbids"):
        ControlledPatchApplier(tmp_path).validate(
            proposal(path=".github/workflows/ci.yml", original="permissions: {}\n", replacement="")
        )


def test_rejects_ambiguous_edit(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("demo==1.0\ndemo==1.0\n", encoding="utf-8")
    with pytest.raises(PatchRejected, match="found 2"):
        ControlledPatchApplier(tmp_path).validate(proposal())
