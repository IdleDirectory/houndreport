"""Account and host hygiene."""

from __future__ import annotations

import re

from ..model import Finding, Severity, worst
from ..sids import is_protected, rid
from . import check
from .kerberos import is_managed_account

# Operating systems out of vendor support (no ESU assumed). Windows 10 non-LTSC ended 2025-10-14.
UNSUPPORTED_OS = [
    re.compile(p, re.I) for p in (
        r"windows\s*(nt|2000|xp|vista)\b",
        r"windows\s*(7|8|8\.1)\b",
        r"server\s*(2000|2003|2008|2012)\b",
        r"windows\s*10(?!.*\blts[bc]\b)",
    )
]


def is_unsupported_os(os_name: str | None) -> bool:
    return bool(os_name) and any(p.search(os_name) for p in UNSUPPORTED_OS)


@check("hygiene", ids=("HR-HYG-001", "HR-HYG-002", "HR-HYG-003", "HR-HYG-004", "HR-HYG-005"))
def hygiene(ctx):
    g = ctx.graph
    stale_days = ctx.options.stale_days

    protected_closure: set[str] = set()
    for oid in g.objects:
        if is_protected(oid):
            protected_closure.add(oid)
            protected_closure |= g.members_of(oid)

    orphaned = []
    for obj in g.objects_of("User") + g.objects_of("Group"):
        if obj.props.get("admincount") and obj.oid not in protected_closure and not ctx.is_tier0(obj.oid):
            orphaned.append(ctx.affected(obj.oid, Severity.LOW, enabled=obj.enabled))

    stale = []
    for obj in g.objects_of("User") + g.objects_of("Computer"):
        if not obj.enabled or rid(obj.oid) == 502:
            continue
        last = obj.props.get("lastlogontimestamp")
        age = ctx.days_since(last)
        if age is None:  # never logged on: judge by creation date
            created = ctx.days_since(obj.props.get("whencreated"))
            if created is None or created <= stale_days:
                continue
            reason = f"Never logged on; created {created} days ago"
        elif age > stale_days:
            reason = f"Last logon {age} days ago"
        else:
            continue
        stale.append(ctx.affected(obj.oid, Severity.MEDIUM, last_logon=ctx.fmt_ts(last),
                                  days_inactive=age, reason=reason, privileged=ctx.is_privileged(obj.oid)))

    never_expires = []
    for user in g.objects_of("User"):
        if user.enabled and user.props.get("pwdneverexpires") and not is_managed_account(user.props):
            sev = Severity.HIGH if ctx.is_privileged(user.oid) else Severity.MEDIUM
            never_expires.append(ctx.affected(user.oid, sev, privileged=ctx.is_privileged(user.oid),
                                              password_last_set=ctx.fmt_ts(user.props.get("pwdlastset")),
                                              password_age_days=ctx.days_since(user.props.get("pwdlastset"))))

    unsupported, no_laps = [], []
    for comp in g.objects_of("Computer"):
        if not comp.enabled:
            continue
        os_name = comp.props.get("operatingsystem")
        if is_unsupported_os(os_name):
            sev = Severity.CRITICAL if ctx.is_dc(comp.oid) else Severity.HIGH
            unsupported.append(ctx.affected(comp.oid, sev, operating_system=os_name,
                                            last_logon=ctx.fmt_ts(comp.props.get("lastlogontimestamp"))))
        if comp.props.get("haslaps") is False and not ctx.is_dc(comp.oid):
            no_laps.append(ctx.affected(comp.oid, Severity.MEDIUM, operating_system=os_name))

    yield Finding(
        id="HR-HYG-001",
        title="Orphaned adminCount attribute",
        severity=Severity.LOW,
        category="Hygiene",
        description=(
            "These objects have adminCount=1 but are no longer members of any protected group. SDProp stops "
            "managing them, leaving inheritance disabled and a stale ACL, and many tools still treat them as "
            "privileged, which hides real changes."
        ),
        remediation=(
            "Clear adminCount, re-enable ACL inheritance on the object and confirm the account no longer "
            "needs elevated access. Review why the account was privileged in the first place."
        ),
        affected=orphaned,
        controls=["3.1.5", "3.4.2"],
    )
    yield Finding(
        id="HR-HYG-002",
        title=f"Stale enabled accounts (inactive > {stale_days} days)",
        severity=Severity.MEDIUM,
        category="Hygiene",
        description=(
            f"Enabled user and computer accounts with no logon in more than {stale_days} days, relative to "
            "the newest logon timestamp in the data set. Dormant accounts are attractive targets because "
            "their compromise goes unnoticed."
        ),
        remediation=(
            "Disable inactive accounts after confirming with owners, move them to a quarantine OU and delete "
            "them after a retention period. Automate this with a scheduled review."
        ),
        affected=stale,
        controls=["3.5.6", "3.1.1"],
    )
    yield Finding(
        id="HR-HYG-003",
        title="Passwords set to never expire",
        severity=worst((a.severity for a in never_expires), Severity.MEDIUM),
        category="Hygiene",
        description=(
            "Enabled users with DONT_EXPIRE_PASSWORD keep the same password indefinitely, so a leaked or "
            "cracked password stays valid. Privileged accounts with this flag are rated High."
        ),
        remediation=(
            "Clear 'Password never expires' and rely on long passphrases with a rotation or breach-detection "
            "policy. Move service accounts to gMSAs, which rotate automatically."
        ),
        affected=never_expires,
        controls=["3.5.7"],
    )
    yield Finding(
        id="HR-HYG-004",
        title="Unsupported operating systems",
        severity=worst((a.severity for a in unsupported), Severity.HIGH),
        category="Hygiene",
        description=(
            "Enabled computers report an operating system that no longer receives security updates "
            "(unless covered by Extended Security Updates, which this data cannot show)."
        ),
        remediation=(
            "Upgrade or decommission these systems. If that is not yet possible, enrol them in ESU, isolate "
            "them on the network and remove privileged logons from them."
        ),
        affected=unsupported,
        controls=["3.14.1", "3.11.3", "3.4.1"],
    )
    yield Finding(
        id="HR-HYG-005",
        title="Computers without LAPS",
        severity=Severity.MEDIUM,
        category="Hygiene",
        description=(
            "Enabled non-DC computers have no LAPS-managed local administrator password. Shared local "
            "administrator passwords let one compromised machine unlock many others (pass-the-hash)."
        ),
        remediation=(
            "Deploy Windows LAPS (or legacy Microsoft LAPS) to all workstations and member servers and "
            "restrict who can read the password attributes."
        ),
        affected=no_laps,
        controls=["3.5.7", "3.1.5"],
    )
