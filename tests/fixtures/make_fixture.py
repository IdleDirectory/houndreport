"""Generate the synthetic CORP.LOCAL SharpHound CE fixture used by the tests.

Everything here is invented. Run ``python tests/fixtures/make_fixture.py`` to regenerate
``tests/fixtures/corp/``. Users are written as meta version 5, everything else as version 6.

Planted issues (see tests for the expected findings):
  * SVC_BACKUP: Domain Admin with an SPN (privileged Kerberoast); CAROL can reset its password
  * SVC_SQL / SVC_WEB: Kerberoastable; SVC_WEB has constrained delegation w/ protocol transition to DC01
  * ALICE: AS-REP roastable, member of HELPDESK (local admin on WS01, where JANE (DA) is logged on)
  * SVC_SYNC: non-default DCSync
  * DOMAIN USERS: local admin on WS02; GenericWrite on the Default Domain Controllers Policy GPO
  * APP01: unconstrained delegation, Server 2012 R2, RBCD from WS02$
  * OLD01 / BOB: stale; OLD_ADMIN: orphaned adminCount
  * ADCS: ESC1 (VULNTEMPLATE), ESC2 (ANYPURPOSE), ESC3 (ENROLLAGENT), ESC4 (WEBSERVER)
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).parent / "corp"

DOM = "CORP.LOCAL"
DSID = "S-1-5-21-1000-2000-3000"
REF = 1767225600  # 2026-01-01T00:00:00Z
DAY = 86400
RECENT = REF - 2 * DAY
STALE = REF - 200 * DAY
OLD = REF - 900 * DAY

DC_OU = "0A1B2C3D-0000-4000-8000-000000000001"
WS_OU = "0A1B2C3D-0000-4000-8000-000000000002"
USERS_CN = "0A1B2C3D-0000-4000-8000-000000000003"
DDP = "31B2F340-016D-11D2-945F-00C04FB984F9"
DDCP = "6AC1786C-016F-11D2-945F-00C04FB984F9"
WSGPO = "0A1B2C3D-0000-4000-8000-0000000000A1"
CA = "0A1B2C3D-0000-4000-8000-0000000000C1"

CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
ANY_PURPOSE = "2.5.29.37.0"
CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
EMAIL = "1.3.6.1.5.5.7.3.4"


def sid(r: int) -> str:
    return f"{DSID}-{r}"


def wk(s: str) -> str:
    return f"{DOM}-{s}"


def ref(oid: str, t: str) -> dict:
    return {"ObjectIdentifier": oid, "ObjectType": t}


def ace(principal: str, right: str, ptype: str = "Group", inherited: bool = False) -> dict:
    return {"PrincipalSID": principal, "PrincipalType": ptype, "RightName": right, "IsInherited": inherited}


def results(items: list) -> dict:
    return {"Results": items, "Collected": True, "FailureReason": None}


def user(r: int, sam: str, *, enabled=True, spns=(), asrep=False, pne=False, admincount=False,
         last=RECENT, aces=(), deleg=(), t2a=False, allowed_spns=()) -> dict:
    return {
        "ObjectIdentifier": sid(r),
        "PrimaryGroupSID": sid(513),
        "AllowedToDelegate": [ref(t, "Computer") for t in deleg],
        "HasSIDHistory": [],
        "SPNTargets": [],
        "Aces": list(aces),
        "IsDeleted": False,
        "IsACLProtected": False,
        "Properties": {
            "name": f"{sam.upper()}@{DOM}", "domain": DOM, "domainsid": DSID,
            "samaccountname": sam, "enabled": enabled, "hasspn": bool(spns),
            "serviceprincipalnames": list(spns), "dontreqpreauth": asrep, "pwdneverexpires": pne,
            "admincount": admincount, "lastlogontimestamp": last, "lastlogon": last,
            "pwdlastset": OLD, "whencreated": OLD, "unconstraineddelegation": False,
            "trustedtoauth": t2a, "allowedtodelegate": list(allowed_spns), "sensitive": False,
        },
    }


def computer(r: int, host: str, os_name: str, *, isdc=False, unconstrained=False, laps=False,
             last=RECENT, admins=(), sessions=(), act=(), parent=WS_OU) -> dict:
    return {
        "ObjectIdentifier": sid(r),
        "PrimaryGroupSID": sid(516 if isdc else 515),
        "IsDC": isdc,
        "AllowedToDelegate": [],
        "AllowedToAct": [ref(a, "Computer") for a in act],
        "HasSIDHistory": [],
        "Aces": [],
        "IsDeleted": False,
        "ContainedBy": ref(parent, "OU"),
        "LocalAdmins": results([ref(a, t) for a, t in admins]),
        "RemoteDesktopUsers": results([]),
        "DcomUsers": results([]),
        "PSRemoteUsers": results([]),
        "Sessions": results([{"UserSID": u, "ComputerSID": sid(r)} for u in sessions]),
        "PrivilegedSessions": results([]),
        "RegistrySessions": results([]),
        "Properties": {
            "name": f"{host.upper()}.{DOM}", "domain": DOM, "domainsid": DSID,
            "samaccountname": f"{host.upper()}$", "enabled": True, "isdc": isdc,
            "operatingsystem": os_name, "unconstraineddelegation": unconstrained,
            "trustedtoauth": False, "haslaps": laps, "lastlogontimestamp": last,
            "whencreated": OLD,
        },
    }


def group(r_or_oid, name: str, members=(), aces=()) -> dict:
    oid = sid(r_or_oid) if isinstance(r_or_oid, int) else r_or_oid
    return {
        "ObjectIdentifier": oid,
        "Members": [ref(m, t) for m, t in members],
        "Aces": list(aces),
        "IsDeleted": False,
        "Properties": {"name": f"{name}@{DOM}", "domain": DOM, "domainsid": DSID},
    }


def template(oid: str, name: str, *, ekus, supply=False, approval=False, sigs=0, aces=()) -> dict:
    auth = (not ekus) or bool({CLIENT_AUTH, ANY_PURPOSE} & set(ekus))
    return {
        "ObjectIdentifier": oid,
        "Aces": list(aces),
        "IsDeleted": False,
        "Properties": {
            "name": f"{name}@{DOM}", "domain": DOM, "domainsid": DSID,
            "enrolleesuppliessubject": supply, "requiresmanagerapproval": approval,
            "authorizedsignatures": sigs, "ekus": list(ekus), "effectiveekus": list(ekus),
            "authenticationenabled": auth, "schemaversion": 2,
        },
    }


def build() -> dict[str, tuple[int, list]]:
    users = [
        user(500, "administrator", pne=True, admincount=True),
        user(502, "krbtgt", enabled=False, spns=["kadmin/changepw"], admincount=True),
        user(1101, "svc_sql", spns=["MSSQLSvc/sql01.corp.local:1433"], pne=True),
        user(1102, "alice", asrep=True),
        user(1103, "bob", last=STALE),
        user(1104, "carol"),
        user(1105, "jane", admincount=True),
        user(1106, "old_admin", admincount=True),
        user(1107, "svc_backup", spns=["backup/app01.corp.local"], admincount=True,
             aces=[ace(sid(1104), "ForceChangePassword", "User")]),
        user(1108, "svc_sync"),
        user(1109, "svc_web", spns=["HTTP/web01.corp.local"], deleg=[sid(1000)], t2a=True,
             allowed_spns=["cifs/dc01.corp.local"]),
        user(1110, "dave", enabled=False, last=STALE),
    ]
    groups = [
        group(512, "DOMAIN ADMINS", [(sid(500), "User"), (sid(1105), "User"), (sid(1107), "User")]),
        group(513, "DOMAIN USERS"),
        group(515, "DOMAIN COMPUTERS"),
        group(516, "DOMAIN CONTROLLERS", [(sid(1000), "Computer")]),
        group(519, "ENTERPRISE ADMINS", [(sid(500), "User")]),
        group(wk("S-1-5-32-544"), "ADMINISTRATORS", [(sid(512), "Group"), (sid(519), "Group")]),
        group(1200, "HELPDESK", [(sid(1102), "User")]),
    ]
    computers = [
        computer(1000, "dc01", "Windows Server 2022 Standard", isdc=True, unconstrained=True,
                 admins=[(wk("S-1-5-32-544"), "Group")], parent=DC_OU),
        computer(1301, "ws01", "Windows 10 Pro", admins=[(sid(1200), "Group")], sessions=[sid(1105)]),
        computer(1302, "ws02", "Windows 11 Enterprise", laps=True, admins=[(sid(513), "Group")]),
        computer(1303, "app01", "Windows Server 2012 R2 Standard", unconstrained=True, act=[sid(1302)]),
        computer(1304, "old01", "Windows Server 2008 R2 Enterprise", last=STALE),
    ]
    domains = [{
        "ObjectIdentifier": DSID,
        "Aces": [
            ace(sid(516), "GetChanges"), ace(sid(516), "GetChangesAll"),
            ace(wk("S-1-5-32-544"), "GetChanges"), ace(wk("S-1-5-32-544"), "GetChangesAll"),
            ace(wk("S-1-5-9"), "GetChanges"), ace(wk("S-1-5-9"), "GetChangesAll"),
            ace(sid(498), "GetChanges"),
            ace(sid(1108), "GetChanges", "User"), ace(sid(1108), "GetChangesAll", "User"),
            ace(sid(512), "GenericAll"),
        ],
        "Links": [{"IsEnforced": False, "GUID": DDP}],
        "ChildObjects": [ref(DC_OU, "OU"), ref(WS_OU, "OU"), ref(USERS_CN, "Container")],
        "Trusts": [],
        "GPOChanges": {"LocalAdmins": [], "RemoteDesktopUsers": [], "DcomUsers": [],
                       "PSRemoteUsers": [], "AffectedComputers": []},
        "IsDeleted": False,
        "Properties": {"name": DOM, "domain": DOM, "domainsid": DSID, "functionallevel": "2016"},
    }]
    ous = [
        {"ObjectIdentifier": DC_OU, "Aces": [], "IsDeleted": False,
         "Links": [{"IsEnforced": False, "GUID": DDCP}], "ChildObjects": [ref(sid(1000), "Computer")],
         "ContainedBy": ref(DSID, "Domain"),
         "Properties": {"name": f"DOMAIN CONTROLLERS@{DOM}", "domain": DOM, "blocksinheritance": False}},
        {"ObjectIdentifier": WS_OU, "Aces": [], "IsDeleted": False,
         "Links": [{"IsEnforced": True, "GUID": WSGPO}],
         "ChildObjects": [ref(sid(1301), "Computer"), ref(sid(1302), "Computer"),
                          ref(sid(1303), "Computer"), ref(sid(1304), "Computer")],
         "ContainedBy": ref(DSID, "Domain"),
         "GPOChanges": {"LocalAdmins": [ref(sid(1200), "Group")], "RemoteDesktopUsers": [],
                        "DcomUsers": [], "PSRemoteUsers": [],
                        "AffectedComputers": [ref(sid(1301), "Computer"), ref(sid(1302), "Computer")]},
         "Properties": {"name": f"WORKSTATIONS@{DOM}", "domain": DOM, "blocksinheritance": False}},
    ]
    containers = [
        {"ObjectIdentifier": USERS_CN, "Aces": [], "IsDeleted": False,
         "ChildObjects": [ref(u["ObjectIdentifier"], "User") for u in users],
         "ContainedBy": ref(DSID, "Domain"),
         "Properties": {"name": f"USERS@{DOM}", "domain": DOM}},
    ]
    gpos = [
        {"ObjectIdentifier": DDP, "Aces": [ace(sid(512), "GenericAll")], "IsDeleted": False,
         "Properties": {"name": f"DEFAULT DOMAIN POLICY@{DOM}", "domain": DOM}},
        {"ObjectIdentifier": DDCP, "Aces": [ace(sid(512), "GenericAll"), ace(sid(513), "GenericWrite")],
         "IsDeleted": False,
         "Properties": {"name": f"DEFAULT DOMAIN CONTROLLERS POLICY@{DOM}", "domain": DOM}},
        {"ObjectIdentifier": WSGPO, "Aces": [ace(sid(1200), "GenericAll")], "IsDeleted": False,
         "Properties": {"name": f"WORKSTATION BASELINE@{DOM}", "domain": DOM}},
    ]
    t = "0A1B2C3D-0000-4000-8000-0000000000"
    templates = [
        template(t + "D1", "VULNTEMPLATE", ekus=[CLIENT_AUTH], supply=True,
                 aces=[ace(sid(513), "Enroll"), ace(wk("S-1-5-11"), "Enroll")]),
        template(t + "D2", "ANYPURPOSE", ekus=[ANY_PURPOSE], aces=[ace(sid(513), "Enroll")]),
        template(t + "D3", "ENROLLAGENT", ekus=[CERT_REQUEST_AGENT], aces=[ace(sid(513), "Enroll")]),
        template(t + "D4", "WEBSERVER", ekus=[SERVER_AUTH], supply=True,
                 aces=[ace(sid(512), "Enroll"), ace(sid(1200), "GenericWrite")]),
        template(t + "D5", "USER", ekus=[CLIENT_AUTH, EMAIL], aces=[ace(sid(513), "Enroll")]),
        template(t + "D6", "UNPUBLISHED", ekus=[CLIENT_AUTH], supply=True, aces=[ace(sid(513), "Enroll")]),
    ]
    cas = [{
        "ObjectIdentifier": CA,
        "Aces": [ace(sid(512), "ManageCA")],
        "IsDeleted": False,
        "HostingComputer": sid(1000),
        "EnabledCertTemplates": [ref(t + s, "CertTemplate") for s in ("D1", "D2", "D3", "D4", "D5")],
        "Properties": {"name": f"CORP-CA@{DOM}", "domain": DOM, "caname": "CORP-CA",
                       "dnshostname": "dc01.corp.local"},
    }]
    return {
        "users": (5, users), "groups": (6, groups), "computers": (6, computers),
        "domains": (6, domains), "ous": (6, ous), "containers": (6, containers),
        "gpos": (6, gpos), "certtemplates": (6, templates), "enterprisecas": (6, cas),
    }


def write(out: Path = OUT) -> None:
    out.mkdir(parents=True, exist_ok=True)
    # Always LF, so the committed fixture is identical on every OS.
    for ftype, (version, data) in build().items():
        doc = {"data": data, "meta": {"methods": 0, "type": ftype, "count": len(data), "version": version}}
        (out / f"20260101000000_{ftype}.json").write_text(json.dumps(doc, indent=1), encoding="utf-8", newline="\n")
    widgets = {"data": [], "meta": {"type": "widgets", "count": 0, "version": 6}}
    (out / "20260101000000_widgets.json").write_text(json.dumps(widgets), encoding="utf-8", newline="\n")
    (out / "broken.json").write_text("{not json", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    write()
    print(f"wrote fixture to {OUT}")
