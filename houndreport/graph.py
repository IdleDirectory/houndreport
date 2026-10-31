"""Directed AD object graph built from SharpHound data.

Edges point from the principal that holds a capability to the object it affects
(BloodHound's convention), e.g. ``user -MemberOf-> group``, ``group -AdminTo-> computer``,
``computer -HasSession-> user``. Each node pair has one networkx edge whose ``rels`` attribute
maps relationship kind -> ``{"inherited": bool, "via": [str]}``.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterator

import networkx as nx

from .loader import RawData
from .model import ADObject
from .sids import RID_NAMES, WELL_KNOWN_SIDS, domain_sid, normalize, rid, well_known

KIND_BY_TYPE = {
    "users": "User", "computers": "Computer", "groups": "Group", "domains": "Domain",
    "gpos": "GPO", "ous": "OU", "containers": "Container", "certtemplates": "CertTemplate",
    "enterprisecas": "EnterpriseCA", "rootcas": "RootCA", "aiacas": "AIACA",
    "ntauthstores": "NTAuthStore", "issuancepolicies": "IssuancePolicy",
}

HOST_ACCESS_FIELDS = (
    ("LocalAdmins", "AdminTo"),
    ("RemoteDesktopUsers", "CanRDP"),
    ("PSRemoteUsers", "CanPSRemote"),
    ("DcomUsers", "ExecuteDCOM"),
)
SESSION_FIELDS = ("Sessions", "PrivilegedSessions", "RegistrySessions")


class ADGraph:
    def __init__(self) -> None:
        self.g = nx.DiGraph()
        self.objects: dict[str, ADObject] = {}
        self.domain_names: dict[str, str] = {}  # domain SID -> domain name
        self.coverage: Counter[str] = Counter()  # collection-method coverage counters
        self.files: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self._membership: nx.DiGraph | None = None

    # -- construction -------------------------------------------------------------------
    def add_object(self, obj: ADObject) -> None:
        existing = self.objects.get(obj.oid)
        if existing is not None and not existing.placeholder:
            existing.props.update({k: v for k, v in obj.props.items() if k not in existing.props})
            return
        self.objects[obj.oid] = obj
        self.g.add_node(obj.oid)

    def ensure(self, oid: object, kind: str | None = "Base") -> ADObject:
        oid = normalize(oid)
        obj = self.objects.get(oid)
        if obj is None:
            obj = ADObject(oid, kind or "Base", self._fallback_name(oid), placeholder=True)
            self.objects[oid] = obj
            self.g.add_node(oid)
        elif obj.placeholder and obj.kind == "Base" and kind and kind != "Base":
            obj.kind = kind
        return obj

    def _fallback_name(self, oid: str) -> str:
        wk = well_known(oid)
        if wk in WELL_KNOWN_SIDS:
            prefix = oid[: -len(wk) - 1] if oid != wk else ""
            label = WELL_KNOWN_SIDS[wk].upper()
            return f"{label}@{prefix}" if prefix else label
        r = rid(oid)
        if r in RID_NAMES:
            domain = self.domain_names.get(domain_sid(oid) or "")
            label = RID_NAMES[r].upper()
            return f"{label}@{domain}" if domain else f"{label} ({oid})"
        return oid

    def add_edge(self, src: str, dst: str, kind: str, *, inherited: bool = False,
                 via: str | None = None) -> None:
        if not src or not dst or src == dst:
            return
        if not self.g.has_edge(src, dst):
            self.g.add_edge(src, dst, rels={})
        rels = self.g[src][dst]["rels"]
        rel = rels.get(kind)
        if rel is None:
            rels[kind] = {"inherited": inherited, "via": [via] if via else []}
        else:
            rel["inherited"] = rel["inherited"] and inherited
            if via and via not in rel["via"]:
                rel["via"].append(via)
        if kind == "MemberOf":
            self._membership = None

    # -- lookups ------------------------------------------------------------------------
    def obj(self, oid: str) -> ADObject:
        return self.objects[oid]

    def name(self, oid: str) -> str:
        obj = self.objects.get(oid)
        return obj.name if obj else oid

    def kind(self, oid: str) -> str:
        obj = self.objects.get(oid)
        return obj.kind if obj else "Base"

    def objects_of(self, kind: str, include_placeholders: bool = False) -> list[ADObject]:
        return [o for o in self.objects.values()
                if o.kind == kind and (include_placeholders or not o.placeholder)]

    def edges(self, kind: str | None = None) -> Iterator[tuple[str, str, str, dict]]:
        for u, v, data in self.g.edges(data=True):
            for k, rel in data["rels"].items():
                if kind is None or k == kind:
                    yield u, v, k, rel

    def in_edges(self, oid: str) -> Iterator[tuple[str, str, dict]]:
        for u, _, data in self.g.in_edges(oid, data=True):
            for k, rel in data["rels"].items():
                yield u, k, rel

    def out_edges(self, oid: str) -> Iterator[tuple[str, str, dict]]:
        for _, v, data in self.g.out_edges(oid, data=True):
            for k, rel in data["rels"].items():
                yield v, k, rel

    @property
    def membership(self) -> nx.DiGraph:
        """Sub-graph of MemberOf edges only (member -> group)."""
        if self._membership is None:
            mg = nx.DiGraph()
            mg.add_edges_from((u, v) for u, v, _, _ in self.edges("MemberOf"))
            self._membership = mg
        return self._membership

    def groups_of(self, oid: str) -> set[str]:
        """Every group ``oid`` belongs to, transitively."""
        mg = self.membership
        return nx.descendants(mg, oid) if oid in mg else set()

    def members_of(self, group: str) -> set[str]:
        """Every principal that belongs to ``group``, transitively."""
        mg = self.membership
        return nx.ancestors(mg, group) if group in mg else set()


# -- building -----------------------------------------------------------------------------
def _ref(entry: Any) -> tuple[str, str] | None:
    if isinstance(entry, dict) and entry.get("ObjectIdentifier"):
        return entry["ObjectIdentifier"], entry.get("ObjectType") or "Base"
    if isinstance(entry, str) and entry:
        return entry, "Base"
    return None


def _refs(value: Any) -> list[tuple[str, str]]:
    return [r for r in map(_ref, value or []) if r] if isinstance(value, list) else []


def _results(value: Any) -> list:
    """SharpHound CE wraps collected lists as {"Results": [...], "Collected": bool}."""
    if isinstance(value, dict):
        results = value.get("Results")
        return results if isinstance(results, list) else []
    return value if isinstance(value, list) else []


def build_graph(raw: RawData) -> ADGraph:
    graph = ADGraph()
    graph.files = list(raw.files)
    graph.warnings = list(raw.warnings)

    # Pass 1: objects, so relationships can reference objects defined in later files.
    for ftype, items in raw.by_type.items():
        kind = KIND_BY_TYPE[ftype]
        for item in items:
            if not item.get("ObjectIdentifier") or item.get("IsDeleted"):
                continue
            oid = normalize(item["ObjectIdentifier"])
            props = dict(item.get("Properties") or {})
            if "IsDC" in item:
                props.setdefault("isdc", bool(item["IsDC"]))
            domain = str(props.get("domain") or "").upper()
            graph.add_object(ADObject(oid, kind, str(props.get("name") or oid), domain, props))
            if kind == "Domain":
                graph.domain_names[oid] = str(props.get("name") or oid)
            elif props.get("domainsid") and domain:
                graph.domain_names.setdefault(normalize(props["domainsid"]), domain)

    # Pass 2: relationships.
    for ftype, items in raw.by_type.items():
        kind = KIND_BY_TYPE[ftype]
        for item in items:
            if item.get("ObjectIdentifier") and not item.get("IsDeleted"):
                _ingest_relationships(graph, kind, item)

    _add_dcsync_edges(graph)
    return graph


def _ingest_relationships(graph: ADGraph, kind: str, item: dict[str, Any]) -> None:
    oid = normalize(item["ObjectIdentifier"])

    def node(ref: tuple[str, str]) -> str:
        return graph.ensure(ref[0], ref[1]).oid

    for ace in item.get("Aces") or []:
        if isinstance(ace, dict) and ace.get("PrincipalSID") and ace.get("RightName"):
            principal = graph.ensure(ace["PrincipalSID"], ace.get("PrincipalType") or "Base").oid
            graph.add_edge(principal, oid, ace["RightName"], inherited=bool(ace.get("IsInherited")))

    parent = _ref(item.get("ContainedBy"))
    if parent:
        graph.add_edge(node(parent), oid, "Contains")
    for child in _refs(item.get("ChildObjects")):
        graph.add_edge(oid, node(child), "Contains")
    for link in item.get("Links") or []:
        if isinstance(link, dict) and link.get("GUID"):
            gpo = graph.ensure(link["GUID"], "GPO").oid
            graph.add_edge(gpo, oid, "GPLink", via="enforced" if link.get("IsEnforced") else None)

    for target in _refs(item.get("HasSIDHistory")):
        graph.add_edge(oid, node(target), "HasSIDHistory")
    for target in _refs(item.get("AllowedToDelegate")):
        graph.add_edge(oid, node(target), "AllowedToDelegate")
    for principal in _refs(item.get("AllowedToAct")):
        graph.add_edge(node(principal), oid, "AllowedToAct")
    for member in _refs(item.get("Members")):
        graph.add_edge(node(member), oid, "MemberOf")
    if item.get("PrimaryGroupSID"):
        graph.add_edge(oid, graph.ensure(item["PrimaryGroupSID"], "Group").oid, "MemberOf")

    if kind == "Computer":
        for field_, rel in HOST_ACCESS_FIELDS:
            value = item.get(field_)
            if isinstance(value, dict) and value.get("Collected"):
                graph.coverage[field_] += 1
            for principal in _refs(_results(value)):
                graph.add_edge(node(principal), oid, rel)
        for field_ in SESSION_FIELDS:
            value = item.get(field_)
            if isinstance(value, dict) and value.get("Collected"):
                graph.coverage[field_] += 1
            for session in _results(value):
                if isinstance(session, dict) and session.get("UserSID"):
                    user = graph.ensure(session["UserSID"], "User").oid
                    computer = graph.ensure(session.get("ComputerSID") or oid, "Computer").oid
                    graph.add_edge(computer, user, "HasSession")

    gpo_changes = item.get("GPOChanges")
    if isinstance(gpo_changes, dict):
        computers = [node(c) for c in _refs(gpo_changes.get("AffectedComputers"))]
        via = f"GPO-applied on {graph.name(oid)}"
        for field_, rel in HOST_ACCESS_FIELDS:
            for principal in _refs(gpo_changes.get(field_)):
                p = node(principal)
                for computer in computers:
                    graph.add_edge(p, computer, rel, via=via)

    if kind == "EnterpriseCA":
        for template in _refs(item.get("EnabledCertTemplates")):
            graph.add_edge(node(template), oid, "PublishedTo")
        if item.get("HostingComputer"):
            graph.add_edge(graph.ensure(item["HostingComputer"], "Computer").oid, oid, "HostsCAService")
    if kind == "Domain":
        graph.obj(oid).props["_trusts"] = item.get("Trusts") or []


def _add_dcsync_edges(graph: ADGraph) -> None:
    """Derive DCSync: GetChangesAll plus GetChanges (directly or through a group)."""
    for domain in graph.objects_of("Domain"):
        holders: dict[str, set[str]] = {"GetChanges": set(), "GetChangesAll": set()}
        for src, kind, _ in graph.in_edges(domain.oid):
            if kind in holders:
                holders[kind].add(src)
        changes = holders["GetChanges"]
        for principal in holders["GetChangesAll"]:
            if principal in changes or changes & graph.groups_of(principal):
                graph.add_edge(principal, domain.oid, "DCSync")
