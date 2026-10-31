"""Tier 0 identification."""

from __future__ import annotations

from dataclasses import dataclass, field

from .graph import ADGraph
from .sids import RID_NAMES, TIER0_RIDS, TIER0_WELL_KNOWN, WELL_KNOWN_SIDS, is_broad, rid, well_known


@dataclass
class Tier0:
    principals: set[str]  # privileged identities, DCs and domain objects
    targets: set[str]  # principals + Tier 0 infrastructure (DC OUs, GPOs linked to Tier 0 containers)
    base: set[str]  # principals before counting DCSync grants (used to tell default from added rights)
    reasons: dict[str, str]
    dcsync: dict[str, list[str]]  # principal -> domains it can DCSync
    dcs: set[str]  # domain controller computer objects
    broad_nested: list[tuple[str, str]] = field(default_factory=list)  # (broad group, Tier 0 group)

    def __contains__(self, oid: object) -> bool:
        return oid in self.principals


def _seed_reason(graph: ADGraph, oid: str) -> str | None:
    obj = graph.obj(oid)
    if obj.kind == "Domain":
        return "Domain object"
    r = rid(oid)
    if r in TIER0_RIDS:
        return f"Built-in privileged principal ({RID_NAMES[r]})"
    wk = well_known(oid)
    if wk in TIER0_WELL_KNOWN:
        return f"Built-in privileged group ({WELL_KNOWN_SIDS[wk]})"
    if obj.kind == "Computer" and obj.props.get("isdc"):
        return "Domain controller"
    return None


def _expand(graph: ADGraph, seeds: set[str], reasons: dict[str, str],
            broad_nested: list[tuple[str, str]]) -> set[str]:
    """Add transitive members of every seed; broad groups are recorded, not absorbed."""
    result = set(seeds)
    for seed in sorted(seeds):
        stack = [seed]
        while stack:
            group = stack.pop()
            for member in sorted(graph.membership.predecessors(group)) if group in graph.membership else ():
                if member in result:
                    continue
                if is_broad(member):
                    if (member, seed) not in broad_nested:
                        broad_nested.append((member, seed))
                    continue
                result.add(member)
                reasons.setdefault(member, f"Member of {graph.name(seed)}")
                stack.append(member)
    return result


def compute_tier0(graph: ADGraph) -> Tier0:
    reasons: dict[str, str] = {}
    for oid in graph.objects:
        why = _seed_reason(graph, oid)
        if why:
            reasons[oid] = why
    broad_nested: list[tuple[str, str]] = []
    base = _expand(graph, set(reasons), reasons, broad_nested)

    dcsync: dict[str, list[str]] = {}
    for principal, domain, _, _ in graph.edges("DCSync"):
        dcsync.setdefault(principal, []).append(domain)
        reasons.setdefault(principal, "Can DCSync (GetChanges + GetChangesAll on the domain)")
    principals = _expand(graph, base | set(dcsync), reasons, broad_nested)

    dc_group_members = set()
    for oid in principals:
        if rid(oid) == 516:
            dc_group_members |= graph.members_of(oid)
    dcs = {o for o in principals if graph.kind(o) == "Computer"
           and (graph.obj(o).props.get("isdc") or o in dc_group_members)}

    targets = set(principals)
    for dc in dcs:
        for parent, kind, _ in graph.in_edges(dc):
            if kind == "Contains" and graph.kind(parent) == "OU":
                targets.add(parent)
                reasons.setdefault(parent, "OU containing domain controllers")
    for container in [t for t in targets if graph.kind(t) in ("Domain", "OU")]:
        for gpo, kind, _ in graph.in_edges(container):
            if kind == "GPLink":
                targets.add(gpo)
                reasons.setdefault(gpo, f"GPO linked to {graph.name(container)}")
    for obj in graph.objects_of("Container"):
        if obj.name.upper().startswith("ADMINSDHOLDER@"):
            targets.add(obj.oid)
            reasons.setdefault(obj.oid, "AdminSDHolder template")

    return Tier0(principals=principals, targets=targets, base=base, reasons=reasons,
                 dcsync=dcsync, dcs=dcs, broad_nested=broad_nested)
