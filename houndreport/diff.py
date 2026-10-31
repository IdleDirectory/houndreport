"""Compare two findings.json documents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import SEVERITY_RANK


class DiffError(ValueError):
    pass


def load_findings(path: str | Path) -> dict[str, Any]:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DiffError(f"{path}: cannot read findings JSON ({exc})") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list):
        raise DiffError(f"{path}: not a houndreport findings.json (no 'findings' list)")
    return doc


def _meta(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "client": doc.get("client", ""),
        "generated_at": doc.get("generated_at"),
        "reference_date": doc.get("reference_date"),
        "risk": doc.get("risk", {}),
        "domains": [d.get("name") for d in doc.get("domains", [])],
        "redacted": bool(doc.get("redacted")),
    }


def _brief(f: dict[str, Any]) -> dict[str, Any]:
    return {"id": f["id"], "title": f.get("title", ""), "severity": f.get("severity", "Info"),
            "affected_count": len(f.get("affected", [])), "affected": f.get("affected", [])}


def diff_documents(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    old_by_id = {f["id"]: f for f in old["findings"]}
    new_by_id = {f["id"]: f for f in new["findings"]}

    def by_severity(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(items, key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f["id"]))

    persisting = []
    for fid in old_by_id.keys() & new_by_id.keys():
        o, n = old_by_id[fid], new_by_id[fid]
        o_items = {a["key"]: a for a in o.get("affected", [])}
        n_items = {a["key"]: a for a in n.get("affected", [])}
        persisting.append({
            **_brief(n),
            "old_severity": o.get("severity"),
            "severity_changed": o.get("severity") != n.get("severity"),
            "new_objects": [n_items[k] for k in sorted(n_items.keys() - o_items.keys())],
            "resolved_objects": [o_items[k] for k in sorted(o_items.keys() - n_items.keys())],
            "persisting_objects": len(o_items.keys() & n_items.keys()),
        })

    warnings = []
    if bool(old.get("redacted")) != bool(new.get("redacted")):
        warnings.append("One report is redacted and the other is not; affected-object keys will not match.")
    if [d.get("name") for d in old.get("domains", [])] != [d.get("name") for d in new.get("domains", [])]:
        warnings.append("The reports cover different domains.")

    new_findings = by_severity([_brief(new_by_id[i]) for i in new_by_id.keys() - old_by_id.keys()])
    resolved = by_severity([_brief(old_by_id[i]) for i in old_by_id.keys() - new_by_id.keys()])
    persisting = by_severity(persisting)
    old_score = (old.get("risk") or {}).get("score")
    new_score = (new.get("risk") or {}).get("score")
    return {
        "old": _meta(old),
        "new": _meta(new),
        "warnings": warnings,
        "risk_delta": (new_score - old_score) if isinstance(old_score, int) and isinstance(new_score, int) else None,
        "new_findings": new_findings,
        "resolved_findings": resolved,
        "persisting_findings": persisting,
        "summary": {
            "new": len(new_findings),
            "resolved": len(resolved),
            "persisting": len(persisting),
            "new_objects": sum(len(p["new_objects"]) for p in persisting) + sum(f["affected_count"] for f in new_findings),
            "resolved_objects": (sum(len(p["resolved_objects"]) for p in persisting)
                                 + sum(f["affected_count"] for f in resolved)),
        },
    }


def render_diff_html(result: dict[str, Any]) -> str:
    from .report import environment
    return environment().get_template("diff.html.j2").render(d=result)


def worst_new_severity(result: dict[str, Any]) -> int:
    """Highest severity rank among new findings and new objects in persisting findings (-1 if none)."""
    ranks = [SEVERITY_RANK.get(f["severity"], 0) for f in result["new_findings"]]
    for p in result["persisting_findings"]:
        for a in p["new_objects"]:
            ranks.append(SEVERITY_RANK.get(a.get("severity") or p["severity"], 0))
    return max(ranks, default=-1)
