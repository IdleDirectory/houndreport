"""Well-known SIDs/RIDs and helpers for BloodHound object identifiers.

BloodHound CE writes domain-local well-known SIDs with a domain prefix, e.g.
``CORP.LOCAL-S-1-5-32-544``; :func:`well_known` accepts both that and the bare form.
"""

from __future__ import annotations

WELL_KNOWN_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-3-0": "Creator Owner",
    "S-1-5-4": "Interactive",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "Local System",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicator",
    "S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "Remote Desktop Users",
}

RID_NAMES = {
    498: "Enterprise Read-only Domain Controllers",
    500: "Administrator",
    501: "Guest",
    502: "krbtgt",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers",
    526: "Key Admins",
    527: "Enterprise Key Admins",
}

TIER0_RIDS = frozenset({500, 502, 512, 516, 518, 519, 526, 527})
TIER0_WELL_KNOWN = frozenset(
    {"S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551", "S-1-5-9"}
)
# Groups whose members get adminCount=1 stamped by SDProp.
PROTECTED_RIDS = TIER0_RIDS | {521}
PROTECTED_WELL_KNOWN = TIER0_WELL_KNOWN | {"S-1-5-32-552"}
# Principals that hold replication rights in a default domain.
DEFAULT_DCSYNC_RIDS = frozenset({498, 512, 516, 519, 521})
DEFAULT_DCSYNC_WELL_KNOWN = frozenset({"S-1-5-32-544", "S-1-5-9"})
# Principals that (nearly) every account belongs to.
BROAD_RIDS = frozenset({513, 514, 515})
BROAD_WELL_KNOWN = frozenset({"S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546"})
# ACE trustees that never represent a real attacker position.
IGNORED_ACE_PRINCIPALS = frozenset({"S-1-3-0", "S-1-5-10", "S-1-5-18"})


def normalize(oid: object) -> str:
    return str(oid).strip().upper()


def well_known(oid: str) -> str | None:
    """Bare well-known SID for ``S-1-5-11`` or ``CORP.LOCAL-S-1-5-11``; None otherwise."""
    if oid.startswith("S-1-"):
        return None if oid.startswith("S-1-5-21-") else oid
    idx = oid.find("-S-1-")
    return oid[idx + 1:] if idx > 0 else None


def rid(oid: str) -> int | None:
    if oid.startswith("S-1-5-21-"):
        parts = oid.split("-")
        if len(parts) == 8 and parts[-1].isdigit():
            return int(parts[-1])
    return None


def domain_sid(oid: str) -> str | None:
    return oid.rsplit("-", 1)[0] if rid(oid) is not None else None


def is_broad(oid: str) -> bool:
    return rid(oid) in BROAD_RIDS or well_known(oid) in BROAD_WELL_KNOWN


def is_protected(oid: str) -> bool:
    return rid(oid) in PROTECTED_RIDS or well_known(oid) in PROTECTED_WELL_KNOWN


def is_default_dcsync(oid: str) -> bool:
    return rid(oid) in DEFAULT_DCSYNC_RIDS or well_known(oid) in DEFAULT_DCSYNC_WELL_KNOWN
