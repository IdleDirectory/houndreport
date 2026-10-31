"""Load SharpHound CE collector output from a .zip, a directory, or a single .json file."""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

KNOWN_TYPES = frozenset({
    "users", "computers", "groups", "domains", "gpos", "ous", "containers", "certtemplates",
    "enterprisecas", "rootcas", "aiacas", "ntauthstores", "issuancepolicies",
})
SUPPORTED_VERSIONS = frozenset({5, 6})

_TYPE_FROM_NAME = re.compile(r"(?:^|[_\-/\\])(" + "|".join(sorted(KNOWN_TYPES)) + r")\.json$", re.I)


@dataclass
class RawData:
    by_type: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    files: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _iter_sources(path: Path) -> Iterator[tuple[str, bytes]]:
    if path.is_dir():
        for p in sorted(path.rglob("*.json")):
            yield p.relative_to(path).as_posix(), p.read_bytes()
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for info in sorted(zf.infolist(), key=lambda i: i.filename):
                if not info.is_dir() and info.filename.lower().endswith(".json"):
                    yield info.filename, zf.read(info)
    elif path.is_file() and path.suffix.lower() == ".json":
        yield path.name, path.read_bytes()
    else:
        raise ValueError(f"{path} is not a directory, .zip archive or .json file")


def load(path: str | Path) -> RawData:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    raw = RawData()
    for name, blob in _iter_sources(path):
        try:
            doc = json.loads(blob.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raw.warnings.append(f"{name}: not valid JSON ({exc}); skipped")
            continue
        if not isinstance(doc, dict) or not isinstance(doc.get("data"), list):
            raw.warnings.append(f"{name}: no top-level 'data' array; skipped")
            continue
        meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}

        ftype = str(meta.get("type") or "").lower()
        if not ftype:
            match = _TYPE_FROM_NAME.search(name)
            ftype = match.group(1).lower() if match else ""
        if ftype not in KNOWN_TYPES:
            raw.warnings.append(f"{name}: unknown data type {ftype or '(none)'!r}; skipped")
            continue

        try:
            version = int(meta["version"]) if meta.get("version") is not None else None
        except (TypeError, ValueError):
            version = None
        if version is None:
            raw.warnings.append(f"{name}: no meta.version; parsing as version 6")
        elif version < min(SUPPORTED_VERSIONS):
            raw.warnings.append(
                f"{name}: meta.version {version} is a legacy (pre-CE) format and is not supported; skipped"
            )
            continue
        elif version not in SUPPORTED_VERSIONS:
            raw.warnings.append(f"{name}: meta.version {version} is newer than tested; parsing best-effort")

        data = [item for item in doc["data"] if isinstance(item, dict)]
        count = meta.get("count")
        if isinstance(count, int) and count != len(data):
            raw.warnings.append(f"{name}: meta.count is {count} but {len(data)} objects were found")
        raw.by_type.setdefault(ftype, []).extend(data)
        raw.files.append({"file": name, "type": ftype, "version": version, "count": len(data)})

    if not raw.files:
        raw.warnings.append("no usable SharpHound data files were found")
    return raw
