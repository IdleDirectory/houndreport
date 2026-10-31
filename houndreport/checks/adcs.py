"""Active Directory Certificate Services misconfigurations (ESC1-ESC4).

Only runs when certtemplates data is present. A template counts as published when an
Enterprise CA lists it in EnabledCertTemplates; without any CA data every template is
treated as published and the finding says so.
"""

from __future__ import annotations

from ..model import Affected, Finding, Severity, worst
from ..sids import is_broad
from . import check

CLIENT_AUTH_EKUS = frozenset({
    "1.3.6.1.5.5.7.3.2",       # Client Authentication
    "1.3.6.1.5.2.3.4",         # PKINIT Client Authentication
    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
    "2.5.29.37.0",             # Any Purpose
})
ANY_PURPOSE = "2.5.29.37.0"
CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
ENROLL_RIGHTS = frozenset({"Enroll", "AllExtendedRights", "GenericAll"})
WRITE_RIGHTS = frozenset({"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
                          "WriteProperty", "WritePKINameFlag", "WritePKIEnrollmentFlag"})
REFS = ["https://posts.specterops.io/certified-pre-owned-d95910965cd2"]


def _ekus(props: dict) -> list[str]:
    value = props.get("effectiveekus")
    if value is None:
        value = props.get("ekus")
    return list(value or [])


def _auth_capable(props: dict) -> bool:
    if "authenticationenabled" in props:
        return bool(props["authenticationenabled"])
    ekus = _ekus(props)
    return not ekus or bool(CLIENT_AUTH_EKUS & set(ekus))


def _no_issuance_controls(props: dict) -> bool:
    return not props.get("requiresmanagerapproval") and not (props.get("authorizedsignatures") or 0)


@check("adcs", ids=("HR-ADCS-ESC1", "HR-ADCS-ESC2", "HR-ADCS-ESC3", "HR-ADCS-ESC4"))
def adcs(ctx):
    g = ctx.graph
    templates = g.objects_of("CertTemplate")
    if not templates:
        return
    have_ca_data = bool(g.objects_of("EnterpriseCA"))

    def published_to(oid: str) -> list[str]:
        return sorted(g.name(ca) for ca, kind, _ in g.out_edges(oid) if kind == "PublishedTo")

    def principals_with(oid: str, rights: frozenset[str]) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        for principal, kind, _ in g.in_edges(oid):
            if kind in rights and not ctx.is_tier0(principal):
                found.setdefault(principal, []).append(kind)
        return found

    def entry(tmpl, principals: dict[str, list[str]], **extra) -> Affected:
        broad = any(p in ctx.broad_closure for p in principals)
        details = {
            "principals": sorted(g.name(p) for p in principals),
            "rights": sorted({r for rights in principals.values() for r in rights}),
            "published_on": published_to(tmpl.oid) or (["unknown (no CA data)"] if not have_ca_data else []),
            "ekus": _ekus(tmpl.props),
            **extra,
        }
        return ctx.affected(tmpl.oid, Severity.CRITICAL if broad else Severity.HIGH, **details)

    esc1, esc2, esc3, esc4 = [], [], [], []
    for tmpl in templates:
        p = tmpl.props
        published = bool(published_to(tmpl.oid)) or not have_ca_data
        enrollers = principals_with(tmpl.oid, ENROLL_RIGHTS)
        ekus = _ekus(p)
        if published and enrollers and _no_issuance_controls(p):
            if p.get("enrolleesuppliessubject") and _auth_capable(p):
                esc1.append(entry(tmpl, enrollers))
            if not ekus or ANY_PURPOSE in ekus:
                esc2.append(entry(tmpl, enrollers))
            if CERT_REQUEST_AGENT in ekus:
                esc3.append(entry(tmpl, enrollers))
        writers = principals_with(tmpl.oid, WRITE_RIGHTS)
        if writers:
            esc4.append(entry(tmpl, writers, published=published))

    common_fix = (" Restrict enrollment to the specific groups that need the template, and remove "
                  "Domain Users / Authenticated Users / Domain Computers from enrollment rights.")
    yield Finding(
        id="HR-ADCS-ESC1",
        title="ADCS ESC1: enrollee-supplied subject on an authentication template",
        severity=worst((a.severity for a in esc1), Severity.HIGH),
        category="ADCS",
        description=(
            "Low-privileged principals can enroll in a published template that allows client authentication, "
            "lets the requester supply the subject (SAN) and needs no approval or authorized signature. They "
            "can request a certificate as any user, including a Domain Admin, and authenticate with it."
        ),
        remediation="Clear CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, or require CA manager approval." + common_fix,
        affected=esc1, controls=["3.1.5", "3.5.2", "3.13.10"], references=REFS,
    )
    yield Finding(
        id="HR-ADCS-ESC2",
        title="ADCS ESC2: Any Purpose or no-EKU template",
        severity=worst((a.severity for a in esc2), Severity.HIGH),
        category="ADCS",
        description=(
            "Low-privileged principals can enroll in a published template whose certificates are valid for "
            "any purpose (Any Purpose EKU or no EKU). Such certificates can be used for client authentication "
            "and, with no EKU, as a subordinate CA certificate."
        ),
        remediation="Replace Any Purpose / empty EKUs with the specific EKUs required." + common_fix,
        affected=esc2, controls=["3.1.5", "3.13.10"], references=REFS,
    )
    yield Finding(
        id="HR-ADCS-ESC3",
        title="ADCS ESC3: enrollment agent template open to low-privileged users",
        severity=worst((a.severity for a in esc3), Severity.HIGH),
        category="ADCS",
        description=(
            "Low-privileged principals can obtain a Certificate Request Agent certificate. Enrollment agents "
            "can request certificates on behalf of other users, including administrators, unless enrollment "
            "agent restrictions are configured on the CA."
        ),
        remediation=("Restrict enrollment in agent templates to a dedicated group and configure Enrollment Agent "
                     "restrictions on the CA." + common_fix),
        affected=esc3, controls=["3.1.5", "3.13.10"], references=REFS,
    )
    yield Finding(
        id="HR-ADCS-ESC4",
        title="ADCS ESC4: certificate template writable by non-Tier 0 principals",
        severity=worst((a.severity for a in esc4), Severity.HIGH),
        category="ADCS",
        description=(
            "Non-Tier 0 principals can modify these certificate templates. They can reconfigure a template "
            "into an ESC1-style template, request a certificate as a Domain Admin and revert the change."
        ),
        remediation=("Remove write permissions (GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty) from "
                     "non-Tier 0 principals on certificate templates; treat templates and CAs as Tier 0."),
        affected=esc4, controls=["3.1.5", "3.1.7", "3.13.10"], references=REFS,
    )
