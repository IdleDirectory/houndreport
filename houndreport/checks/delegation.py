"""Kerberos delegation: unconstrained, constrained and resource-based constrained (RBCD)."""

from __future__ import annotations

from collections import defaultdict

from ..model import Finding, Severity, worst
from ..sids import is_broad
from . import check


@check("delegation", ids=("HR-DELEG-001", "HR-DELEG-002", "HR-DELEG-003"))
def delegation(ctx):
    g = ctx.graph

    unconstrained = []
    for obj in g.objects_of("Computer") + g.objects_of("User"):
        if obj.enabled and obj.props.get("unconstraineddelegation") and not ctx.is_dc(obj.oid):
            unconstrained.append(ctx.affected(
                obj.oid, Severity.CRITICAL,
                operating_system=obj.props.get("operatingsystem"),
                tier0=ctx.is_tier0(obj.oid),
            ))

    targets_by_src: dict[str, list[str]] = defaultdict(list)
    for src, dst, _, _ in g.edges("AllowedToDelegate"):
        targets_by_src[src].append(dst)
    constrained = []
    for src, targets in targets_by_src.items():
        obj = g.obj(src)
        if not obj.enabled or ctx.is_tier0(src):
            continue
        protocol_transition = bool(obj.props.get("trustedtoauth"))
        tier0_targets = [t for t in targets if ctx.is_tier0(t)]
        if tier0_targets:
            sev = Severity.CRITICAL if protocol_transition else Severity.HIGH
        else:
            sev = Severity.HIGH if protocol_transition else Severity.MEDIUM
        constrained.append(ctx.affected(
            src, sev,
            targets=sorted(g.name(t) for t in targets),
            target_spns=list(obj.props.get("allowedtodelegate") or []),
            protocol_transition=protocol_transition,
            tier0_targets=sorted(g.name(t) for t in tier0_targets),
        ))

    rbcd = []
    for principal, computer, _, _ in g.edges("AllowedToAct"):
        if ctx.is_tier0(principal):
            continue
        if ctx.is_tier0(computer):
            sev = Severity.CRITICAL
        elif is_broad(principal):
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM
        rbcd.append(ctx.affected(
            computer, sev, key=f"{principal}->{computer}",
            principal=g.name(principal), principal_type=g.kind(principal),
            computer_tier0=ctx.is_tier0(computer),
        ))

    yield Finding(
        id="HR-DELEG-001",
        title="Unconstrained delegation on non-DC accounts",
        severity=Severity.CRITICAL,
        category="Delegation",
        description=(
            "Accounts trusted for unconstrained delegation receive a forwardable TGT from every user that "
            "authenticates to them. An attacker who controls one of these hosts can coerce a domain "
            "controller to authenticate (e.g. PrinterBug/PetitPotam) and capture its TGT, which leads "
            "straight to DCSync."
        ),
        remediation=(
            "Remove 'Trust this computer for delegation to any service'. Replace it with constrained "
            "delegation or RBCD scoped to the services required. Add privileged accounts to Protected "
            "Users or mark them 'Account is sensitive and cannot be delegated'."
        ),
        affected=unconstrained,
        controls=["3.1.5", "3.4.6"],
        references=["https://attack.mitre.org/techniques/T1558/"],
    )
    yield Finding(
        id="HR-DELEG-002",
        title="Constrained delegation",
        severity=worst((a.severity for a in constrained), Severity.MEDIUM),
        category="Delegation",
        description=(
            "These accounts can impersonate any user to the listed services (S4U2Proxy). With protocol "
            "transition (TrustedToAuthForDelegation) no user interaction is needed at all. Delegation to "
            "services on Tier 0 hosts lets whoever controls the account take over those hosts."
        ),
        remediation=(
            "Review every msDS-AllowedToDelegateTo entry. Remove delegation to domain controllers and other "
            "Tier 0 hosts, disable protocol transition unless it is required, and protect privileged "
            "users with Protected Users or the 'sensitive and cannot be delegated' flag."
        ),
        affected=constrained,
        controls=["3.1.5", "3.4.6"],
    )
    yield Finding(
        id="HR-DELEG-003",
        title="Resource-based constrained delegation (RBCD) configured",
        severity=worst((a.severity for a in rbcd), Severity.MEDIUM),
        category="Delegation",
        description=(
            "These computers list another principal in msDS-AllowedToActOnBehalfOfOtherIdentity. That "
            "principal can impersonate any non-protected user, including administrators, to the computer. "
            "Unexpected RBCD entries are a common persistence and lateral-movement technique."
        ),
        remediation=(
            "Confirm each RBCD entry is required and documented. Remove unexpected entries, set "
            "ms-DS-MachineAccountQuota to 0 and restrict who can write msDS-AllowedToActOnBehalfOfOtherIdentity."
        ),
        affected=rbcd,
        controls=["3.1.5"],
    )
