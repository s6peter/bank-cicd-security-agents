"""Validate and apply narrowly scoped model-proposed edits."""

from __future__ import annotations

import fnmatch
import os
import tempfile
from pathlib import Path

from .models import PatchProposal
from .policy import load_policy


class PatchRejected(ValueError):
    pass


class ControlledPatchApplier:
    def __init__(self, repo: str | Path, policy_path: str | Path | None = None):
        self.repo = Path(repo).resolve()
        self.policy = load_policy(policy_path)

    def validate(self, proposal: PatchProposal) -> dict[Path, str]:
        limits = self.policy["patch_limits"]
        if proposal.confidence < float(self.policy["auto_patch"]["minimum_agent_confidence"]):
            raise PatchRejected("Agent confidence is below the automatic patch threshold")
        if not proposal.edits:
            raise PatchRejected("Proposal contains no edits")
        if len(proposal.edits) > int(limits["maximum_files"]):
            raise PatchRejected("Proposal changes too many files")

        prepared: dict[Path, str] = {}
        changed_lines = 0
        for edit in proposal.edits:
            relative = Path(edit.path)
            if relative.is_absolute() or ".." in relative.parts:
                raise PatchRejected(f"Unsafe path: {edit.path}")
            normalized = relative.as_posix()
            if any(fnmatch.fnmatch(normalized, pattern) for pattern in self.policy["never_modify"]):
                raise PatchRejected(f"Policy forbids agent edits to {normalized}")
            target = (self.repo / relative).resolve()
            if self.repo not in target.parents:
                raise PatchRejected(f"Path escapes repository: {edit.path}")
            if not target.is_file():
                raise PatchRejected(f"Target does not exist: {edit.path}")

            current = prepared.get(target, target.read_text(encoding="utf-8"))
            occurrences = current.count(edit.original)
            if occurrences != 1:
                raise PatchRejected(
                    f"Expected one exact match in {edit.path}, found {occurrences}; "
                    "refusing ambiguity"
                )
            changed_lines += max(edit.original.count("\n") + 1, edit.replacement.count("\n") + 1)
            prepared[target] = current.replace(edit.original, edit.replacement, 1)

        if changed_lines > int(limits["maximum_changed_lines"]):
            raise PatchRejected("Proposal exceeds the changed-line limit")
        return prepared

    def apply(self, proposal: PatchProposal, dry_run: bool = True) -> list[str]:
        prepared = self.validate(proposal)
        if dry_run:
            return [str(path.relative_to(self.repo)) for path in prepared]

        for target, content in prepared.items():
            mode = target.stat().st_mode
            descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temporary, mode)
                os.replace(temporary, target)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        return [str(path.relative_to(self.repo)) for path in prepared]
