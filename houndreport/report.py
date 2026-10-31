"""Write report.html, findings.json and per-finding CSV files."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader

from .model import SEVERITY_RANK
from .svg import gauge_svg, path_svg

HTML_AFFECTED_CAP = 500
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def fmt_value(value: Any) -> str:
    if value is None or value == "" or value == []:
        return "—"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple)):
        return ", ".join(fmt_value(v) for v in value)
    return str(value)


def _label(key: str) -> str:
    return key.replace("_", " ").capitalize()


def environment() -> Environment:
    env = Environment(loader=PackageLoader("houndreport", "templates"), autoescape=True,
                      trim_blocks=True, lstrip_blocks=True)
    env.filters["fmt"] = fmt_value
    return env


def _finding_view(f: dict[str, Any]) -> dict[str, Any]:
    keys: list[str] = []
    for a in f["affected"]:
        for k in a["details"]:
            if k not in keys:
                keys.append(k)
    rows = [dict(a, rank=SEVERITY_RANK.get(a["severity"] or "", -1)) for a in f["affected"][:HTML_AFFECTED_CAP]]
    search = " ".join([f["id"], f["title"], f["category"]] + [a["name"] for a in rows]).lower()
    return dict(f, rank=SEVERITY_RANK[f["severity"]], rows=rows, search=search,
                truncated=len(f["affected"]) > HTML_AFFECTED_CAP,
                columns=[{"key": k, "label": _label(k)} for k in keys])


def render_html(doc: dict[str, Any]) -> str:
    top = doc["options"]["top_paths"]
    paths = [dict(p, svg=path_svg(p, i)) for i, p in enumerate(doc["attack_paths"][:top])]
    return environment().get_template("report.html.j2").render(
        doc=doc, s=doc["summary"], findings=[_finding_view(f) for f in doc["findings"]],
        paths=paths, gauge=gauge_svg(doc["risk"]["score"]),
        sev_order=["Critical", "High", "Medium", "Low", "Info"],
    )


def _csv_cell(value: Any) -> str:
    text = fmt_value(value) if not isinstance(value, str) else value
    if isinstance(value, str) and text.startswith(CSV_FORMULA_PREFIXES):
        text = "'" + text  # neutralise spreadsheet formula injection
    return text


def write_csv(finding: dict[str, Any], path: Path) -> None:
    detail_keys: list[str] = []
    for a in finding["affected"]:
        for k in a["details"]:
            if k not in detail_keys:
                detail_keys.append(k)
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(["finding_id", "key", "name", "type", "objectid", "severity"] + detail_keys)
        for a in finding["affected"]:
            writer.writerow([_csv_cell(v) for v in (finding["id"], a["key"], a["name"], a["type"],
                                                    a["objectid"], a["severity"] or "")]
                            + [_csv_cell(a["details"].get(k)) for k in detail_keys])


def write_outputs(doc: dict[str, Any], output_dir: str | Path) -> dict[str, Path]:
    out = Path(output_dir)
    csv_dir = out / "csv"
    csv_dir.mkdir(parents=True, exist_ok=True)
    for stale in csv_dir.glob("HR-*.csv"):  # drop CSVs of built-in findings that no longer apply
        stale.unlink()
    paths = {"html": out / "report.html", "json": out / "findings.json", "csv_dir": csv_dir}
    paths["html"].write_text(render_html(doc), encoding="utf-8")
    paths["json"].write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    for finding in doc["findings"]:
        write_csv(finding, csv_dir / f"{finding['id']}.csv")
    return paths
