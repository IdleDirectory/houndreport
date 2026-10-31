"""Shortest attack paths from non-privileged principals to Tier 0.

A single multi-source BFS runs backwards from every Tier 0 target over traversable edges,
which gives each node its distance to Tier 0 and the next hop on one shortest path.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .explain import TRAVERSABLE, explain
from .graph import ADGraph
from .model import AttackPath, Hop
from .sids import BROAD_WELL_KNOWN, is_broad, well_known
from .tier0 import Tier0

MAX_PATHS = 1000
_PRIORITY = {kind: i for i, kind in enumerate(TRAVERSABLE)}


@dataclass
class PathResult:
    paths: list[AttackPath]  # unique paths, ranked
    enabled_users: int  # enabled non-Tier 0 users
    users_with_path: int  # ... of which can reach Tier 0
    truncated: bool = False

    @property
    def users_with_path_pct(self) -> float:
        return round(100.0 * self.users_with_path / self.enabled_users, 1) if self.enabled_users else 0.0


def _hop_kind(graph: ADGraph, src: str, dst: str) -> str:
    kinds = [k for k in graph.g[src][dst]["rels"] if k in _PRIORITY]
    return min(kinds, key=_PRIORITY.__getitem__)


def compute_attack_paths(graph: ADGraph, tier0: Tier0) -> PathResult:
    targets = tier0.targets
    # Reverse adjacency restricted to traversable edges that start outside Tier 0.
    reverse: dict[str, list[str]] = {}
    for u, v, data in graph.g.edges(data=True):
        if u in targets or not any(k in _PRIORITY for k in data["rels"]):
            continue
        reverse.setdefault(v, []).append(u)

    dist: dict[str, int] = {}
    nxt: dict[str, str] = {}
    queue: deque[str] = deque()
    for t in sorted(targets):
        dist[t] = 0
        queue.append(t)
    while queue:
        node = queue.popleft()
        for pred in sorted(reverse.get(node, ())):
            if pred not in dist:
                dist[pred] = dist[node] + 1
                nxt[pred] = node
                queue.append(pred)

    users = [u for u in graph.objects_of("User") if u.enabled and u.oid not in tier0.principals]
    enabled_user_ids = {u.oid for u in users}
    users_with_path = sum(1 for u in users if u.oid in dist)

    def impact(oid: str) -> int:
        if graph.kind(oid) == "User":
            return 1
        if well_known(oid) in BROAD_WELL_KNOWN:
            return len(enabled_user_ids)
        return len(graph.members_of(oid) & enabled_user_ids)

    candidates = [u.oid for u in users] + [
        g.oid for g in graph.objects_of("Group", include_placeholders=True) if g.oid not in tier0.principals
    ]
    best: dict[tuple[str, ...], AttackPath] = {}
    for source in candidates:
        if dist.get(source, 0) == 0:
            continue
        nodes = [source]
        while dist[nodes[-1]] > 0:
            nodes.append(nxt[nodes[-1]])
        hops = []
        for a, b in zip(nodes, nodes[1:]):
            kind = _hop_kind(graph, a, b)
            hops.append(Hop(a, graph.name(a), graph.kind(a), b, graph.name(b), graph.kind(b), kind,
                            explain(kind, graph.name(a), graph.name(b))))
        # Paths differing only in leading MemberOf hops describe the same weakness.
        first_real = next((i for i, h in enumerate(hops) if h.kind != "MemberOf"), len(hops))
        key = tuple(nodes[first_real:])
        target = nodes[-1]
        path = AttackPath(source, graph.name(source), graph.kind(source), target, graph.name(target),
                          graph.kind(target), tier0.reasons.get(target, "Tier 0"), impact(source), hops)
        current = best.get(key)
        if current is None or (path.impact, -len(path.hops)) > (current.impact, -len(current.hops)):
            best[key] = path

    ranked = sorted(best.values(),
                    key=lambda p: (len(p.hops), -int(is_broad(p.source)), -p.impact, p.source_name))
    return PathResult(paths=ranked[:MAX_PATHS], enabled_users=len(users),
                      users_with_path=users_with_path, truncated=len(ranked) > MAX_PATHS)
