"""Expose computed attack paths as a diffable finding."""

from __future__ import annotations

from ..model import Affected, Finding, Severity, worst
from ..sids import is_broad
from . import check


@check("paths", ids=("HR-PATH-001",))
def paths(ctx):
    if ctx.paths is None:
        return
    affected = []
    for path in ctx.paths.paths:
        broad = is_broad(path.source) or path.source in ctx.broad_closure
        affected.append(Affected(
            name=path.source_name, objectid=path.source, type=path.source_type, key=path.key,
            severity=Severity.CRITICAL if broad or path.impact > 1 else Severity.HIGH,
            details={
                "target": path.target_name,
                "hops": len(path.hops),
                "impacted_users": path.impact,
                "path": " -> ".join([path.source_name] + [f"[{h.kind}] {h.dst_name}" for h in path.hops]),
            },
        ))
    pct = ctx.paths.users_with_path_pct
    yield Finding(
        id="HR-PATH-001",
        title="Attack paths from non-privileged principals to Tier 0",
        severity=worst((a.severity for a in affected), Severity.HIGH),
        category="Attack paths",
        description=(
            f"{ctx.paths.users_with_path} of {ctx.paths.enabled_users} enabled non-Tier 0 users ({pct}%) can "
            "reach a Tier 0 object by chaining group memberships, ACLs, local admin rights, sessions and "
            "delegation. Each row is the shortest path from a distinct starting point; paths that only differ "
            "by group nesting at the start are merged under the group with the widest membership."
        ),
        remediation=(
            "Break each path at its cheapest link, usually the first non-membership hop: remove the excessive "
            "ACE or local admin right, stop Tier 0 logons on lower-tier hosts, or remove delegation. "
            "Re-collect and re-run the report to confirm the path is gone."
        ),
        affected=affected,
        controls=["3.1.5", "3.1.7"],
    )
