"""Hygiene statistics for the report's overview section."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .checks.hygiene import is_unsupported_os
from .context import AnalysisContext


def _pct(part: int, whole: int) -> float:
    return round(100.0 * part / whole, 1) if whole else 0.0


def hygiene_stats(ctx: AnalysisContext) -> dict[str, Any]:
    g = ctx.graph
    stale = ctx.options.stale_days
    users = g.objects_of("User")
    enabled_users = [u for u in users if u.enabled]
    computers = g.objects_of("Computer")
    enabled_computers = [c for c in computers if c.enabled]
    non_dc = [c for c in enabled_computers if not ctx.is_dc(c.oid)]

    def inactive(obj) -> bool:
        age = ctx.days_since(obj.props.get("lastlogontimestamp"))
        return age is not None and age > stale

    laps_known = [c for c in non_dc if "haslaps" in c.props]
    laps_on = sum(1 for c in laps_known if c.props.get("haslaps"))
    os_counts = Counter(str(c.props.get("operatingsystem") or "Unknown") for c in enabled_computers)
    tier0_kinds = Counter(g.kind(o) for o in ctx.tier0.principals)

    return {
        "users": {
            "total": len(users),
            "enabled": len(enabled_users),
            "disabled": len(users) - len(enabled_users),
            "stale_enabled": sum(1 for u in enabled_users if inactive(u)),
            "password_never_expires": sum(1 for u in enabled_users if u.props.get("pwdneverexpires")),
            "password_older_than_1y": sum(1 for u in enabled_users
                                          if (ctx.days_since(u.props.get("pwdlastset")) or 0) > 365),
            "kerberoastable": sum(1 for u in enabled_users
                                  if u.props.get("hasspn") or u.props.get("serviceprincipalnames")),
            "asrep_roastable": sum(1 for u in enabled_users if u.props.get("dontreqpreauth")),
            "admincount": sum(1 for u in enabled_users if u.props.get("admincount")),
        },
        "computers": {
            "total": len(computers),
            "enabled": len(enabled_computers),
            "domain_controllers": len(ctx.tier0.dcs),
            "stale_enabled": sum(1 for c in enabled_computers if inactive(c)),
            "unsupported_os": sum(1 for c in enabled_computers
                                  if is_unsupported_os(c.props.get("operatingsystem"))),
            "unconstrained_delegation": sum(1 for c in non_dc if c.props.get("unconstraineddelegation")),
            "laps_coverage_pct": _pct(laps_on, len(laps_known)),
        },
        "groups": {"total": len(g.objects_of("Group"))},
        "tier0": {
            "principals": len(ctx.tier0.principals),
            "targets": len(ctx.tier0.targets),
            "by_type": dict(sorted(tier0_kinds.items())),
        },
        "os_distribution": [{"name": name, "count": n, "pct": _pct(n, len(enabled_computers)),
                             "unsupported": is_unsupported_os(name)}
                            for name, n in os_counts.most_common()],
        "collection": {
            "objects": len(g.objects),
            "placeholders": sum(1 for o in g.objects.values() if o.placeholder),
            "relationships": sum(len(d["rels"]) for _, _, d in g.g.edges(data=True)),
            "computers_with_local_admin_data": g.coverage.get("LocalAdmins", 0),
            "computers_with_session_data": g.coverage.get("Sessions", 0),
            "cert_templates": len(g.objects_of("CertTemplate")),
            "enterprise_cas": len(g.objects_of("EnterpriseCA")),
        },
    }
