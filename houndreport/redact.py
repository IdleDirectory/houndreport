"""Redaction of user names, host names, domain names and domain SIDs for shareable reports.

Tokens are salted SHA-256 prefixes, so the same input and salt always give the same
pseudonym and redacted reports can still be diffed. Group, OU and GPO names are kept
(minus their domain suffix) because they carry the meaning of most findings.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .graph import ADGraph
from .sids import rid

# Keys whose values are fixed tool text, never collected data.
STATIC_KEYS = frozenset({
    "id", "title", "description", "remediation", "controls", "references", "severity", "category",
    "type", "source_type", "target_type", "src_type", "dst_type", "kind", "right", "rating",
    "schema_version", "tool", "tool_version", "generated_at", "client",
})
KEEP_USER_RIDS = frozenset({500, 501, 502})  # built-in accounts with generic names
MIN_TOKEN = 3


class Redactor:
    def __init__(self, graph: ADGraph, salt: str = "") -> None:
        self.salt = salt
        self.mapping: dict[str, str] = {}
        self._build(graph)
        tokens = sorted((t for t in self.mapping if len(t) >= MIN_TOKEN), key=len, reverse=True)
        self._pattern = (
            re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(map(re.escape, tokens)) + r")(?![A-Za-z0-9_])", re.I)
            if tokens else None
        )

    def _hash(self, kind: str, value: str) -> str:
        return hashlib.sha256(f"{self.salt}\x00{kind}\x00{value.lower()}".encode()).hexdigest()[:8]

    def _add(self, token: str, replacement: str) -> None:
        if token:
            self.mapping.setdefault(token.lower(), replacement)

    def _domain(self, name: str) -> str:
        return f"DOM-{self._hash('domain', name)}"

    def _build(self, graph: ADGraph) -> None:
        domains = {o.domain for o in graph.objects.values() if o.domain}
        domains |= {o.name for o in graph.objects_of("Domain")}
        for domain in sorted(domains, key=len, reverse=True):
            self._add(domain, self._domain(domain))
            self._add(domain.split(".")[0], self._domain(domain))
        for sid in graph.domain_names:
            if sid.startswith("S-1-5-21-"):
                self._add(sid, f"S-1-5-21-REDACTED-{self._hash('sid', sid)}")

        for user in graph.objects_of("User"):
            if rid(user.oid) in KEEP_USER_RIDS:
                continue
            full = user.name
            short = str(user.props.get("samaccountname") or full.split("@")[0])
            pseudo = f"USER-{self._hash('user', full)}"
            dom = self._domain(user.domain) if user.domain else "DOM-REDACTED"
            self._add(full, f"{pseudo}@{dom}")
            self._add(full.split("@")[0], pseudo)
            self._add(short, pseudo)

        for comp in graph.objects_of("Computer"):
            full = comp.name
            short = full.split(".")[0]
            pseudo = f"HOST-{self._hash('host', full)}"
            dom = self._domain(comp.domain) if comp.domain else "DOM-REDACTED"
            self._add(full, f"{pseudo}.{dom}")
            self._add(short, pseudo)
            self._add(str(comp.props.get("samaccountname") or "").rstrip("$"), pseudo)
            dns = str(comp.props.get("dnshostname") or "")
            if dns and dns.lower() != full.lower():
                self._add(dns, f"{pseudo}.{dom}")

    def text(self, value: str) -> str:
        if not self._pattern:
            return value
        return self._pattern.sub(lambda m: self.mapping[m.group(0).lower()], value)

    def apply(self, data: Any, key: str | None = None) -> Any:
        if key in STATIC_KEYS:
            return data
        if isinstance(data, dict):
            return {k: self.apply(v, k) for k, v in data.items()}
        if isinstance(data, list):
            return [self.apply(v) for v in data]
        if isinstance(data, str):
            return self.text(data)
        return data
