"""Overall risk score (0 = no findings, 100 = worst)."""

from __future__ import annotations

import math

from .model import Finding

WEIGHTS = {"Critical": 30.0, "High": 12.0, "Medium": 4.0, "Low": 1.0, "Info": 0.0}
SCALE = 150.0  # raw weight at which the score reaches ~63 (about five Critical findings)


def rating(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Moderate"
    return "Low"


def risk_score(findings: list[Finding]) -> dict:
    """Each finding adds its severity weight, scaled up gently by how many objects it affects."""
    raw = sum(WEIGHTS[f.severity.value] * (1 + math.log10(max(len(f.affected), 1))) for f in findings)
    score = round(100 * (1 - math.exp(-raw / SCALE)))
    return {"score": score, "rating": rating(score), "raw": round(raw, 1)}
