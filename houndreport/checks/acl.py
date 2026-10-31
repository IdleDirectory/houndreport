"""DACL abuse: non-default DCSync and control of Tier 0 objects by non-Tier 0 principals."""

from __future__ import annotations

from ..model import Affected, Finding, Severity
from ..sids import IGNORED_ACE_PRINCIPALS, is_broad, is_default_dcsync, well_known
from . import check

DANGEROUS_RIGHTS = frozenset({
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "ForceChangePassword",
    "AddMember", "AddSelf", "AllExtendedRights", "AddKeyCredentialLink", "WriteSPN",
    "WriteAccountRestrictions", "AddAllowedToAct", "ReadLAPSPassword", "ReadGMSAPassword",
    "SyncLAPSPassword", "WriteGPLink",
})


@check("acl", ids=("HR-ACL-001", "HR-ACL-002"))
def acl(ctx):
    g = ctx.graph

    dcsync = []
    for principal, domains in ctx.tier0.dcsync.items():
        if is_default_dcsync(principal) or ctx.is_dc(principal):
            continue
        # A principal that is Tier 0 anyway gains less from an explicit grant.
        sev = Severity.HIGH if principal in ctx.tier0.base else Severity.CRITICAL
        dcsync.append(ctx.affected(
            principal, sev,
            domains=sorted(g.name(d) for d in domains),
            effective_members=len(g.members_of(principal)),
        ))

    aces = []
    for principal, target, right, rel in g.edges():
        if right not in DANGEROUS_RIGHTS or target not in ctx.tier0.targets:
            continue
        if principal in ctx.tier0.base or well_known(principal) in IGNORED_ACE_PRINCIPALS:
            continue
        aces.append(Affected(
            name=g.name(target), objectid=target, type=g.kind(target),
            key=f"{principal}|{target}|{right}",
            severity=Severity.CRITICAL,
            details={
                "principal": g.name(principal),
                "principal_type": g.kind(principal),
                "right": right,
                "inherited": rel["inherited"],
                "broad_principal": is_broad(principal) or principal in ctx.broad_closure,
                "why_tier0": ctx.tier0.reasons.get(target, ""),
            },
        ))

    yield Finding(
        id="HR-ACL-001",
        title="Non-default principals with DCSync rights",
        severity=Severity.CRITICAL,
        category="Access control",
        description=(
            "These principals hold both 'Replicating Directory Changes' and 'Replicating Directory Changes "
            "All' on the domain. They can retrieve the password hash of any account, including krbtgt, "
            "without touching a domain controller's disk. Only domain controllers and the built-in "
            "administrative groups should hold these rights."
        ),
        remediation=(
            "Remove the replication rights from the domain object's DACL unless there is a documented need "
            "(e.g. Azure AD Connect / Entra Connect sync account). Treat any remaining holder as Tier 0: "
            "protect, monitor (event 4662 with the replication GUIDs) and rotate its credentials."
        ),
        affected=dcsync,
        controls=["3.1.5", "3.1.7"],
        references=["https://attack.mitre.org/techniques/T1003/006/"],
    )
    yield Finding(
        id="HR-ACL-002",
        title="Dangerous permissions over Tier 0 objects held by non-Tier 0 principals",
        severity=Severity.CRITICAL,
        category="Access control",
        description=(
            "Non-privileged principals hold rights such as GenericAll, WriteDacl, WriteOwner, "
            "ForceChangePassword or AddMember over Tier 0 users, groups, computers, GPOs or containers. "
            "Each entry is a one-step escalation to Tier 0 for anyone who controls the principal."
        ),
        remediation=(
            "Remove the listed ACEs (fix inherited entries at the parent OU/container). Make sure "
            "privileged accounts and groups are protected by AdminSDHolder and that delegated "
            "administration (helpdesk, provisioning tools) is scoped to non-Tier 0 OUs only."
        ),
        affected=aces,
        controls=["3.1.5", "3.1.7"],
        references=["https://attack.mitre.org/techniques/T1222/001/"],
    )
