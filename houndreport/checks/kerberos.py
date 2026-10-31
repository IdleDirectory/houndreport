"""Kerberoasting and AS-REP roasting exposure."""

from __future__ import annotations

from ..model import Finding, Severity, worst
from ..sids import rid
from . import check

REFS = ["https://attack.mitre.org/techniques/T1558/003/", "https://attack.mitre.org/techniques/T1558/004/"]


def is_managed_account(props: dict) -> bool:
    return bool(props.get("gmsa") or props.get("msa"))


@check("kerberos", ids=("HR-KERB-001", "HR-KERB-002", "HR-KERB-003"))
def kerberos(ctx):
    privileged, regular, asrep = [], [], []
    for user in ctx.graph.objects_of("User"):
        p = user.props
        if not user.enabled or is_managed_account(p):
            continue
        spns = list(p.get("serviceprincipalnames") or [])
        if (p.get("hasspn") or spns) and rid(user.oid) != 502:
            details = {
                "spns": spns,
                "password_last_set": ctx.fmt_ts(p.get("pwdlastset")),
                "password_age_days": ctx.days_since(p.get("pwdlastset")),
                "admincount": bool(p.get("admincount")),
                "tier0": ctx.is_tier0(user.oid),
            }
            if ctx.is_tier0(user.oid):
                privileged.append(ctx.affected(user.oid, Severity.CRITICAL, **details))
            elif p.get("admincount"):
                privileged.append(ctx.affected(user.oid, Severity.HIGH, **details))
            else:
                regular.append(ctx.affected(user.oid, Severity.MEDIUM, **details))
        if p.get("dontreqpreauth"):
            sev = Severity.CRITICAL if ctx.is_privileged(user.oid) else Severity.HIGH
            asrep.append(ctx.affected(user.oid, sev, tier0=ctx.is_tier0(user.oid),
                                      admincount=bool(p.get("admincount")),
                                      password_age_days=ctx.days_since(p.get("pwdlastset"))))

    yield Finding(
        id="HR-KERB-001",
        title="Kerberoastable privileged accounts",
        severity=worst((a.severity for a in privileged), Severity.HIGH),
        category="Kerberos",
        description=(
            "Privileged user accounts have a service principal name (SPN). Any authenticated user can "
            "request a service ticket for them and crack the account password offline. A cracked Tier 0 "
            "service account is an immediate domain compromise."
        ),
        remediation=(
            "Remove SPNs from privileged accounts, or move the service to a group Managed Service Account "
            "(gMSA). Where an SPN must stay, set a random 30+ character password, enable AES-only "
            "encryption (msDS-SupportedEncryptionTypes) and remove the account from privileged groups."
        ),
        affected=privileged,
        controls=["3.1.5", "3.5.7", "3.5.10"],
        references=REFS[:1],
    )
    yield Finding(
        id="HR-KERB-002",
        title="Kerberoastable user accounts",
        severity=Severity.MEDIUM,
        category="Kerberos",
        description=(
            "Enabled user accounts with SPNs can be Kerberoasted by any domain user. Weak or old passwords "
            "on these service accounts are routinely cracked and give the attacker the service's access."
        ),
        remediation=(
            "Convert service accounts to gMSAs where possible. Otherwise use long random passwords, rotate "
            "them, require AES encryption and remove SPNs that are no longer used."
        ),
        affected=regular,
        controls=["3.5.7", "3.5.10"],
        references=REFS[:1],
    )
    yield Finding(
        id="HR-KERB-003",
        title="AS-REP roastable accounts (pre-authentication disabled)",
        severity=worst((a.severity for a in asrep), Severity.HIGH),
        category="Kerberos",
        description=(
            "These accounts have 'Do not require Kerberos pre-authentication' set. Anyone who can reach a "
            "domain controller, even without credentials, can request encrypted material for them and "
            "crack the password offline."
        ),
        remediation=(
            "Clear the DONT_REQ_PREAUTH flag (userAccountControl 0x400000) on all accounts. If a legacy "
            "application needs it, isolate the account, give it a long random password and monitor "
            "event 4768 with pre-authentication type 0."
        ),
        affected=asrep,
        controls=["3.5.2", "3.5.10"],
        references=REFS[1:],
    )
