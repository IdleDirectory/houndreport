"""Core data model shared by the loader, graph, checks and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from .controls import control_refs


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def rank(self) -> int:
        """Higher is worse."""
        return SEVERITY_RANK[self.value]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        for sev in cls:
            if sev.value.lower() == value.lower():
                return sev
        raise ValueError(f"unknown severity {value!r}")


SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def worst(severities: Iterable[Severity | None], default: Severity) -> Severity:
    present = [s for s in severities if s is not None]
    return max(present, key=lambda s: s.rank) if present else default


@dataclass
class ADObject:
    """One collected (or referenced-only) directory object."""

    oid: str
    kind: str
    name: str
    domain: str = ""
    props: dict[str, Any] = field(default_factory=dict)
    placeholder: bool = False  # referenced by another object but not present in the data

    @property
    def enabled(self) -> bool:
        return self.props.get("enabled", True) is not False


@dataclass
class Affected:
    """An object (or relationship) affected by a finding."""

    name: str
    objectid: str
    type: str
    details: dict[str, Any] = field(default_factory=dict)
    severity: Severity | None = None
    key: str = ""  # stable identity used when diffing reports

    def __post_init__(self) -> None:
        if not self.key:
            self.key = self.objectid

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "objectid": self.objectid,
            "type": self.type,
            "severity": self.severity.value if self.severity else None,
            "details": self.details,
        }


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    affected: list[Affected] = field(default_factory=list)
    controls: list[str] = field(default_factory=list)  # NIST SP 800-171 r2 IDs
    category: str = "General"
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        ordered = sorted(
            self.affected,
            key=lambda a: (-(a.severity.rank if a.severity else -1), a.name.lower(), a.key),
        )
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "remediation": self.remediation,
            "controls": control_refs(self.controls),
            "references": self.references,
            "affected_count": len(self.affected),
            "affected": [a.to_dict() for a in ordered],
        }


@dataclass
class Hop:
    src: str
    src_name: str
    src_type: str
    dst: str
    dst_name: str
    dst_type: str
    kind: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class AttackPath:
    source: str
    source_name: str
    source_type: str
    target: str
    target_name: str
    target_type: str
    target_reason: str
    impact: int  # enabled users that inherit the source's position
    hops: list[Hop]

    @property
    def key(self) -> str:
        return "|".join([self.source] + [h.dst for h in self.hops])

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "source": self.source,
            "source_name": self.source_name,
            "source_type": self.source_type,
            "target": self.target,
            "target_name": self.target_name,
            "target_type": self.target_type,
            "target_reason": self.target_reason,
            "impact": self.impact,
            "length": len(self.hops),
            "hops": [h.to_dict() for h in self.hops],
        }
