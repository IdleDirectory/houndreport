"""Plain-language explanations for each traversable edge kind."""

from __future__ import annotations

EDGE_HELP = {
    "MemberOf": "{src} is a member of {dst} and inherits every right the group holds.",
    "AdminTo": "{src} is a local administrator on {dst}: it can run code as SYSTEM, dump credentials and "
               "impersonate logged-on users.",
    "HasSession": "{dst} has a logon session on {src}; whoever controls {src} can harvest {dst}'s credentials "
                  "or tokens from memory.",
    "CanRDP": "{src} may log on to {dst} over Remote Desktop; with a local privilege escalation this yields "
              "control of the host.",
    "CanPSRemote": "{src} may open a PowerShell Remoting (WinRM) session on {dst}.",
    "ExecuteDCOM": "{src} may execute code on {dst} through DCOM.",
    "AllowedToDelegate": "{src} is trusted for constrained delegation to {dst} and can obtain service tickets "
                         "to it as any user (S4U).",
    "AllowedToAct": "{src} is allowed to act on behalf of other identities to {dst} (RBCD) and can "
                    "impersonate an administrator to it.",
    "AddAllowedToAct": "{src} can write {dst}'s RBCD attribute and grant itself delegation to {dst}.",
    "HasSIDHistory": "{src} carries {dst}'s SID in its SID history and receives {dst}'s access.",
    "DCSync": "{src} holds GetChanges + GetChangesAll on {dst} and can replicate every password hash, "
              "including krbtgt (DCSync).",
    "GenericAll": "{src} has full control (GenericAll) of {dst}.",
    "GenericWrite": "{src} can write attributes of {dst} (e.g. SPN, logon script, key credentials, GPO file path).",
    "WriteDacl": "{src} can modify {dst}'s DACL and grant itself full control.",
    "WriteOwner": "{src} can take ownership of {dst} and then rewrite its DACL.",
    "Owns": "{src} owns {dst}; an owner can always rewrite the DACL.",
    "ForceChangePassword": "{src} can reset {dst}'s password without knowing the current one.",
    "AddMember": "{src} can add arbitrary members to {dst}.",
    "AddSelf": "{src} can add itself to {dst}.",
    "AllExtendedRights": "{src} holds all extended rights on {dst} (password reset, or replication rights on a domain).",
    "AddKeyCredentialLink": "{src} can write {dst}'s msDS-KeyCredentialLink (shadow credentials) and "
                            "authenticate as {dst}.",
    "WriteSPN": "{src} can set an SPN on {dst} and Kerberoast it.",
    "WriteAccountRestrictions": "{src} can modify {dst}'s account restrictions, including its RBCD attribute.",
    "ReadLAPSPassword": "{src} can read {dst}'s LAPS local administrator password.",
    "SyncLAPSPassword": "{src} can replicate confidential attributes, including LAPS passwords, of {dst}.",
    "ReadGMSAPassword": "{src} can retrieve the managed password of {dst}.",
    "Contains": "{src} contains {dst}; control of {src} flows down to {dst} through inherited ACEs.",
    "GPLink": "GPO {src} applies to {dst}; whoever can edit the GPO can run code on everything under {dst}.",
    "WriteGPLink": "{src} can link a GPO to {dst}, applying attacker-controlled policy to its objects.",
}

# Order matters: when two objects are linked by several traversable kinds, the first one listed
# is used to describe the hop.
TRAVERSABLE = tuple(EDGE_HELP)


def explain(kind: str, src: str, dst: str) -> str:
    template = EDGE_HELP.get(kind, "{src} has " + kind + " over {dst}.")
    return template.format(src=src, dst=dst)
