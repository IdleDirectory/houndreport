"""Host access exposure: broad local admin rights and privileged credentials on untrusted hosts."""

from __future__ import annotations

from ..model import Affected, Finding, Severity, worst
from . import check


@check("access", ids=("HR-ACCESS-001", "HR-ACCESS-002", "HR-ACCESS-003"))
def access(ctx):
    g = ctx.graph

    broad_admin = []
    for principal, computer, _, rel in g.edges("AdminTo"):
        if principal not in ctx.broad_closure:
            continue
        sev = Severity.CRITICAL if ctx.is_tier0(computer) else Severity.HIGH
        broad_admin.append(ctx.affected(
            computer, sev, key=f"{principal}|{computer}",
            principal=g.name(principal),
            granted_via=", ".join(rel["via"]) or "Local group membership",
            operating_system=g.obj(computer).props.get("operatingsystem"),
        ))

    sessions = []
    for computer, user, _, _ in g.edges("HasSession"):
        if g.kind(user) != "User" or not ctx.is_tier0(user) or ctx.is_tier0(computer):
            continue
        sessions.append(ctx.affected(
            user, Severity.HIGH, key=f"{computer}|{user}",
            computer=g.name(computer),
            operating_system=g.obj(computer).props.get("operatingsystem"),
            why_tier0=ctx.tier0.reasons.get(user, ""),
        ))

    nested = [
        Affected(name=g.name(broad), objectid=broad, type=g.kind(broad), key=f"{broad}|{group}",
                 severity=Severity.CRITICAL, details={"privileged_group": g.name(group)})
        for broad, group in ctx.tier0.broad_nested
    ]

    yield Finding(
        id="HR-ACCESS-001",
        title="Domain-wide groups have local administrator rights",
        severity=worst((a.severity for a in broad_admin), Severity.HIGH),
        category="Host access",
        description=(
            "Domain Users, Domain Computers, Authenticated Users, Everyone (or a group containing them) are "
            "local administrators on these computers. Every account in the domain can therefore dump "
            "credentials from them and move laterally."
        ),
        remediation=(
            "Remove broad groups from the local Administrators group, both directly and through Group "
            "Policy (Restricted Groups / Local Users and Groups preferences). Grant admin rights per tier "
            "via dedicated groups and use LAPS for the built-in Administrator."
        ),
        affected=broad_admin,
        controls=["3.1.5", "3.1.6", "3.1.7"],
    )
    yield Finding(
        id="HR-ACCESS-002",
        title="Tier 0 sessions on non-Tier 0 hosts",
        severity=Severity.HIGH,
        category="Host access",
        description=(
            "Tier 0 accounts were logged on to workstations or member servers at collection time. Their "
            "credentials or tokens can be harvested by anyone with administrative access to those hosts, "
            "which is a classic path to domain compromise."
        ),
        remediation=(
            "Enforce a tiered administration model: Tier 0 accounts log on only to domain controllers and "
            "Privileged Access Workstations. Apply 'Deny log on' user rights for Tier 0 groups on lower "
            "tiers (or Authentication Policy Silos) and add admins to Protected Users."
        ),
        affected=sessions,
        controls=["3.1.5", "3.1.6", "3.1.12"],
    )
    yield Finding(
        id="HR-ACCESS-003",
        title="Domain-wide group nested in a Tier 0 group",
        severity=Severity.CRITICAL,
        category="Host access",
        description=(
            "A broad group (e.g. Domain Users or Authenticated Users) is a member of a Tier 0 group, so "
            "effectively every account in the domain is privileged."
        ),
        remediation="Remove the broad group from the privileged group immediately and investigate how it was added.",
        affected=nested,
        controls=["3.1.5", "3.1.7"],
    )
