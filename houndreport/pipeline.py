"""End-to-end analysis and the serializable report document."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .attackpaths import PathResult, compute_attack_paths
from .checks import run_checks
from .context import AnalysisContext, Options, infer_reference_time
from .graph import ADGraph, build_graph
from .loader import load
from .model import Finding
from .redact import Redactor
from .scoring import risk_score
from .stats import hygiene_stats
from .tier0 import Tier0, compute_tier0

SCHEMA_VERSION = 1
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")
TIER0_LIST_CAP = 2000


@dataclass
class AnalysisResult:
    graph: ADGraph
    tier0: Tier0
    options: Options
    reference_time: datetime
    findings: list[Finding]
    paths: PathResult
    stats: dict[str, Any]
    risk: dict[str, Any]
    warnings: list[str]


def analyze(input_path: str | Path, options: Options | None = None) -> AnalysisResult:
    options = options or Options()
    raw = load(input_path)
    graph = build_graph(raw)
    tier0 = compute_tier0(graph)
    reference = options.as_of or infer_reference_time(graph)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    ctx = AnalysisContext(graph, tier0, options, reference, warnings=list(raw.warnings))
    ctx.paths = compute_attack_paths(graph, tier0)
    findings = run_checks(ctx)
    return AnalysisResult(
        graph=graph, tier0=tier0, options=options, reference_time=reference, findings=findings,
        paths=ctx.paths, stats=hygiene_stats(ctx), risk=risk_score(findings), warnings=ctx.warnings,
    )


def _narrative(result: AnalysisResult, counts: Counter) -> list[str]:
    lines = [f"Overall exposure is rated {result.risk['rating']} ({result.risk['score']}/100)."]
    crit, high = counts.get("Critical", 0), counts.get("High", 0)
    if crit or high:
        lines.append(f"{crit} critical and {high} high-severity findings were identified.")
    elif result.findings:
        lines.append("No critical or high-severity findings were identified.")
    else:
        lines.append("No findings were identified in the collected data.")
    paths = result.paths
    if paths.enabled_users:
        lines.append(
            f"{paths.users_with_path} of {paths.enabled_users} enabled non-privileged users "
            f"({paths.users_with_path_pct}%) have at least one attack path to Tier 0."
        )
    if result.paths.paths:
        shortest = min(len(p.hops) for p in result.paths.paths)
        lines.append(f"The shortest attack path to Tier 0 is {shortest} hop{'s' if shortest != 1 else ''} long.")
    lines.append(f"Tier 0 contains {len(result.tier0.principals)} privileged principals.")
    if result.findings:
        lines.append(f"Most severe issue: {result.findings[0].title} ({result.findings[0].id}).")
    return lines


def build_document(result: AnalysisResult, *, client_name: str = "",
                   redactor: Redactor | None = None) -> dict[str, Any]:
    counts = Counter(f.severity.value for f in result.findings)
    g = result.graph
    tier0_rows = sorted(
        ({"name": g.name(o), "objectid": o, "type": g.kind(o), "reason": result.tier0.reasons.get(o, "")}
         for o in result.tier0.targets),
        key=lambda r: (r["type"], r["name"]),
    )
    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": "houndreport",
        "tool_version": __version__,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "client": client_name,
        "redacted": redactor is not None,
        "reference_date": result.reference_time.strftime("%Y-%m-%d"),
        "options": {"stale_days": result.options.stale_days, "top_paths": result.options.top_paths},
        "domains": [{"name": d.name, "objectid": d.oid, "functional_level": d.props.get("functionallevel")}
                    for d in sorted(g.objects_of("Domain"), key=lambda d: d.name)],
        "risk": result.risk,
        "summary": {
            "findings_by_severity": {s: counts.get(s, 0) for s in SEVERITY_ORDER},
            "findings": len(result.findings),
            "affected_objects": sum(len(f.affected) for f in result.findings),
            "tier0_principals": len(result.tier0.principals),
            "enabled_users": result.paths.enabled_users,
            "users_with_path": result.paths.users_with_path,
            "users_with_path_pct": result.paths.users_with_path_pct,
            "attack_paths": len(result.paths.paths),
            "attack_paths_truncated": result.paths.truncated,
        },
        "narrative": _narrative(result, counts),
        "findings": [f.to_dict() for f in result.findings],
        "attack_paths": [p.to_dict() for p in result.paths.paths],
        "tier0": tier0_rows[:TIER0_LIST_CAP],
        "stats": result.stats,
        "inputs": {"files": g.files, "warnings": result.warnings},
    }
    return redactor.apply(doc) if redactor else doc
