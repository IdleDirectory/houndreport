"""Shared analysis state handed to every check."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import cached_property
from typing import TYPE_CHECKING, Any

from .graph import ADGraph
from .model import Affected, Severity
from .sids import is_broad
from .tier0 import Tier0

if TYPE_CHECKING:
    from .attackpaths import PathResult


@dataclass
class Options:
    stale_days: int = 90
    top_paths: int = 10
    as_of: datetime | None = None
    skip_checks: tuple[str, ...] = ()


def to_datetime(ts: Any) -> datetime | None:
    """SharpHound timestamps are Unix epoch seconds; 0 / -1 mean 'never'."""
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def infer_reference_time(graph: ADGraph) -> datetime:
    """Approximate the collection time as the newest logon timestamp in the data."""
    newest = 0.0
    for obj in graph.objects.values():
        for key in ("lastlogontimestamp", "lastlogon"):
            value = obj.props.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value > newest:
                newest = float(value)
    return to_datetime(newest) or datetime.now(timezone.utc)


@dataclass
class AnalysisContext:
    graph: ADGraph
    tier0: Tier0
    options: Options
    reference_time: datetime
    paths: "PathResult | None" = None
    warnings: list[str] = field(default_factory=list)

    def is_tier0(self, oid: str) -> bool:
        return oid in self.tier0.principals

    def is_privileged(self, oid: str) -> bool:
        return self.is_tier0(oid) or bool(self.graph.obj(oid).props.get("admincount"))

    def is_dc(self, oid: str) -> bool:
        return oid in self.tier0.dcs

    @cached_property
    def broad_closure(self) -> set[str]:
        """Broad principals plus every group that (transitively) contains one."""
        result: set[str] = set()
        for oid in self.graph.objects:
            if is_broad(oid):
                result.add(oid)
                result |= self.graph.groups_of(oid)
        return result

    def days_since(self, ts: Any) -> int | None:
        when = to_datetime(ts)
        return (self.reference_time - when).days if when else None

    @staticmethod
    def fmt_ts(ts: Any) -> str | None:
        when = to_datetime(ts)
        return when.strftime("%Y-%m-%d") if when else None

    def affected(self, oid: str, severity: Severity | None = None, key: str = "",
                 **details: Any) -> Affected:
        obj = self.graph.obj(oid)
        return Affected(name=obj.name, objectid=obj.oid, type=obj.kind, details=details,
                        severity=severity, key=key)
