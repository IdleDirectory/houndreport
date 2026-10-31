"""Inline SVG drawings for the HTML report (no external assets)."""

from __future__ import annotations

import re
from html import escape

from markupsafe import Markup

NODE_W, NODE_H, GAP, PAD = 460, 44, 46, 2
GAUGE_C = 326.73  # circumference of r=52


def _e(text: object) -> str:
    return escape(str(text), quote=True)


def _trunc(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def path_svg(path: dict, index: int) -> Markup:
    """Vertical chain of nodes with labelled arrows; the last node is the Tier 0 target."""
    nodes = [(path["source_name"], path["source_type"])] + [(h["dst_name"], h["dst_type"]) for h in path["hops"]]
    height = PAD * 2 + len(nodes) * NODE_H + (len(nodes) - 1) * GAP
    marker = f"arrow-{index}"
    label = " to ".join(n for n, _ in nodes)
    out = [
        f'<svg class="path-svg" viewBox="0 0 {NODE_W} {height}" width="{NODE_W}" height="{height}" '
        f'role="img" aria-label="Attack path: {_e(label)}">',
        f'<defs><marker id="{marker}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
        f'orient="auto"><path d="M0,0 L10,5 L0,10 z" class="arrow-head"/></marker></defs>',
    ]
    for i, (name, kind) in enumerate(nodes):
        y = PAD + i * (NODE_H + GAP)
        last = i == len(nodes) - 1
        cls = "t0" if last else re.sub(r"[^a-z0-9]", "", kind.lower()) or "base"
        tag = f"{kind.upper()} · TIER 0" if last else kind.upper()
        out.append(
            f'<g class="node node-{cls}"><title>{_e(name)} ({_e(kind)})</title>'
            f'<rect x="1" y="{y}" width="{NODE_W - 2}" height="{NODE_H}" rx="8"/>'
            f'<text x="14" y="{y + 17}" class="node-kind">{_e(tag)}</text>'
            f'<text x="14" y="{y + 35}" class="node-name">{_e(_trunc(name, 54))}</text></g>'
        )
        if not last:
            y1, y2 = y + NODE_H, y + NODE_H + GAP
            out.append(
                f'<line x1="40" y1="{y1 + 2}" x2="40" y2="{y2 - 3}" class="edge-line" marker-end="url(#{marker})"/>'
                f'<text x="56" y="{y1 + GAP // 2 + 4}" class="edge-label">{_e(path["hops"][i]["kind"])}</text>'
            )
    out.append("</svg>")
    return Markup("".join(out))


def gauge_svg(score: int) -> Markup:
    dash = round(max(0, min(score, 100)) / 100 * GAUGE_C, 2)
    return Markup(
        f'<svg class="gauge" viewBox="0 0 120 120" width="120" height="120" role="img" '
        f'aria-label="Risk score {score} out of 100">'
        f'<circle cx="60" cy="60" r="52" class="gauge-track"/>'
        f'<circle cx="60" cy="60" r="52" class="gauge-value" stroke-dasharray="{dash} {GAUGE_C}" '
        f'transform="rotate(-90 60 60)"/>'
        f'<text x="60" y="68" text-anchor="middle" class="gauge-text">{score}</text></svg>'
    )
