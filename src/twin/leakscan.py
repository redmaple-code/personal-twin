"""Leak scanning: find stored personal values in plaintext files.

Detectors are *values to look for*. They can come from a file the user controls
or directly from the vault's own identifying fields. The report says which file
and line matched and which detector index fired — never the value itself, and
never a prefix of it.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from . import masking
from .errors import TwinError
from .vault import secure_path

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}
TEXT_EXT = {
    ".md", ".txt", ".json", ".jsonl", ".csv", ".tsv", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".conf", ".xml", ".html", ".htm", ".js", ".ts", ".jsx", ".tsx", ".py",
    ".sh", ".ps1", ".bat", ".cmd", ".sql", ".log", ".env", ".properties",
}
MIN_DETECTOR_LEN = 4


@dataclass(frozen=True)
class Detector:
    index: int
    label: str
    value: str


@dataclass
class Hit:
    path: str
    line: int
    detector: int
    label: str

    def as_dict(self) -> dict:
        return {"path": self.path, "line": self.line, "detector": self.detector, "label": self.label}


def load_detector_file(path: Path) -> list[Detector]:
    if not path.exists():
        raise TwinError(f"detector file not found: {path}")
    out: list[Detector] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        label, sep, value = line.partition("\t")
        if not sep:
            value = label
            label = ""
        value = value.strip()
        if len(value) < MIN_DETECTOR_LEN:
            continue
        out.append(Detector(index=len(out) + 1, label=label.strip() or "value", value=value))
    return out


def detectors_from_vault(vault) -> list[Detector]:
    out: list[Detector] = []
    for record in vault.records():
        for name, field in record.fields.items():
            if field.sensitivity in (masking.IDENTIFYING, masking.SECRET) and len(field.value) >= MIN_DETECTOR_LEN:
                out.append(Detector(index=len(out) + 1, label=name, value=field.value))
    return out


def _is_text(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXT:
        return True
    if path.name.startswith(".") and path.suffix == "":
        return True
    return False


def scan(
    roots: list[Path],
    detectors: list[Detector],
    *,
    max_file_bytes: int = 5 << 20,
    allowlist: set[str] | None = None,
) -> list[Hit]:
    allow = {os.path.normcase(a) for a in (allowlist or set())}
    hits: list[Hit] = []
    for root in roots:
        root = Path(root)
        if not root.exists():
            continue
        if root.is_file():
            hits.extend(_scan_file(root, detectors, max_file_bytes, allow))
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                hits.extend(_scan_file(Path(dirpath) / name, detectors, max_file_bytes, allow))
    return hits


def _scan_file(path: Path, detectors: list[Detector], max_bytes: int, allow: set[str]) -> list[Hit]:
    if os.path.normcase(str(path)) in allow:
        return []
    try:
        if not path.is_file() or path.stat().st_size > max_bytes:
            return []
    except OSError:
        return []
    if not _is_text(path):
        return []
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    if b"\x00" in raw[:4096]:
        return []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")

    hits: list[Hit] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for det in detectors:
            if det.value in line:
                hits.append(Hit(path=str(path), line=lineno, detector=det.index, label=det.label))
    return hits


def render_text(hits: list[Hit], scanned: int) -> str:
    if not hits:
        return f"clean: no detector values found in {scanned} location(s)"
    lines = [f"{len(hits)} hit(s) in {scanned} location(s):"]
    for hit in hits:
        lines.append(f"  {hit.path}:{hit.line}  detector #{hit.detector} ({hit.label})")
    return "\n".join(lines)


def write_report(path: Path, hits: list[Hit], scanned: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "scanned": scanned,
        "hits": [h.as_dict() for h in hits],
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    import io

    with io.open(fd, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    secure_path(path)
