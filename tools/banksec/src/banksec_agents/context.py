"""Collect small, allowlisted source windows for Bedrock prompts."""

from __future__ import annotations

from pathlib import Path

from .models import CanonicalFinding

MAX_FILE_BYTES = 200_000
MAX_CONTEXT_CHARS = 30_000
MANIFESTS = (
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "poetry.lock",
    "package.json", "package-lock.json", "yarn.lock", "pom.xml", "build.gradle",
    "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
)


def collect_context(repo: str | Path, finding: CanonicalFinding) -> dict[str, str]:
    root = Path(repo).resolve()
    context: dict[str, str] = {}
    candidates = [finding.location.path, *MANIFESTS]
    budget = MAX_CONTEXT_CHARS
    for name in dict.fromkeys(name for name in candidates if name):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            continue
        target = (root / relative).resolve()
        outside_repo = root not in target.parents
        oversized = target.is_file() and target.stat().st_size > MAX_FILE_BYTES
        if outside_repo or not target.is_file() or oversized:
            continue
        try:
            lines = target.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        if name == finding.location.path:
            start = max(0, finding.location.start_line - 61)
            end = min(len(lines), finding.location.end_line + 60)
            rendered = "\n".join(f"{index + 1}: {lines[index]}" for index in range(start, end))
        else:
            rendered = "\n".join(f"{index + 1}: {line}" for index, line in enumerate(lines))
        rendered = rendered[:budget]
        if rendered:
            context[relative.as_posix()] = rendered
            budget -= len(rendered)
        if budget <= 0:
            break
    return context
