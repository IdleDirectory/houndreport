import pytest
from conftest import names

from houndreport.checks import load_checks, run_checks
from houndreport.checks.hygiene import is_unsupported_os
from houndreport.context import AnalysisContext, Options
from houndreport.model import Severity

EXPECTED = {
    "HR-KERB-001": {"SVC_BACKUP@CORP.LOCAL"},
    "HR-KERB-002": {"SVC_SQL@CORP.LOCAL", "SVC_WEB@CORP.LOCAL"},
    "HR-KERB-003": {"ALICE@CORP.LOCAL"},
    "HR-DELEG-001": {"APP01.CORP.LOCAL"},
    "HR-DELEG-002": {"SVC_WEB@CORP.LOCAL"},
    "HR-DELEG-003": {"APP01.CORP.LOCAL"},
    "HR-ACL-001": {"SVC_SYNC@CORP.LOCAL"},
    "HR-ACL-002": {"SVC_BACKUP@CORP.LOCAL", "DEFAULT DOMAIN CONTROLLERS POLICY@CORP.LOCAL"},
    "HR-ACCESS-001": {"WS02.CORP.LOCAL"},
    "HR-ACCESS-002": {"JANE@CORP.LOCAL"},
    "HR-HYG-001": {"OLD_ADMIN@CORP.LOCAL"},
    "HR-HYG-002": {"BOB@CORP.LOCAL", "OLD01.CORP.LOCAL"},
    "HR-HYG-003": {"ADMINISTRATOR@CORP.LOCAL", "SVC_SQL@CORP.LOCAL"},
    "HR-HYG-004": {"WS01.CORP.LOCAL", "APP01.CORP.LOCAL", "OLD01.CORP.LOCAL"},
    "HR-HYG-005": {"WS01.CORP.LOCAL", "APP01.CORP.LOCAL", "OLD01.CORP.LOCAL"},
    "HR-ADCS-ESC1": {"VULNTEMPLATE@CORP.LOCAL"},
    "HR-ADCS-ESC2": {"ANYPURPOSE@CORP.LOCAL"},
    "HR-ADCS-ESC3": {"ENROLLAGENT@CORP.LOCAL"},
    "HR-ADCS-ESC4": {"WEBSERVER@CORP.LOCAL"},
}


@pytest.mark.parametrize("finding_id", sorted(EXPECTED))
def test_expected_affected_objects(findings, finding_id):
    assert names(findings[finding_id]) == EXPECTED[finding_id]


def test_no_unexpected_findings(findings):
    assert set(findings) == set(EXPECTED) | {"HR-PATH-001"}


def test_severities(findings):
    assert findings["HR-KERB-001"].severity is Severity.CRITICAL
    assert findings["HR-KERB-002"].severity is Severity.MEDIUM
    assert findings["HR-DELEG-002"].severity is Severity.CRITICAL  # protocol transition to a DC
    assert findings["HR-ACL-001"].affected[0].severity is Severity.CRITICAL
    assert findings["HR-HYG-003"].severity is Severity.HIGH  # privileged Administrator
    assert findings["HR-ACCESS-001"].severity is Severity.HIGH


def test_findings_sorted_by_severity(result):
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_ace_finding_details(findings):
    by_key = {a.key.split("|")[2]: a for a in findings["HR-ACL-002"].affected}
    assert by_key["GenericWrite"].details["principal"] == "DOMAIN USERS@CORP.LOCAL"
    assert by_key["GenericWrite"].details["broad_principal"] is True
    assert by_key["ForceChangePassword"].details["principal"] == "CAROL@CORP.LOCAL"


def test_unpublished_template_not_esc1(findings):
    assert "UNPUBLISHED@CORP.LOCAL" not in names(findings["HR-ADCS-ESC1"])
    esc1 = findings["HR-ADCS-ESC1"].affected[0]
    assert "AUTHENTICATED USERS@CORP.LOCAL" in esc1.details["principals"]
    assert esc1.details["published_on"] == ["CORP-CA@CORP.LOCAL"]


def test_controls_have_cmmc_ids(findings):
    controls = {c["nist"]: c["cmmc"] for f in findings.values() for c in f.to_dict()["controls"]}
    assert controls["3.1.5"] == "AC.L2-3.1.5"
    assert controls["3.5.6"] == "IA.L2-3.5.6"
    assert controls["3.14.1"] == "SI.L2-3.14.1"
    assert controls["3.13.10"] == "SC.L2-3.13.10"


def test_stale_days_option(result):
    ctx = AnalysisContext(result.graph, result.tier0, Options(stale_days=500), result.reference_time)
    ctx.paths = result.paths
    by_id = {f.id: f for f in run_checks(ctx)}
    assert "HR-HYG-002" not in by_id  # nothing is 500 days stale


def test_skip_checks(result):
    ctx = AnalysisContext(result.graph, result.tier0, Options(skip_checks=("adcs", "HR-HYG-005")),
                          result.reference_time)
    ctx.paths = result.paths
    ids = {f.id for f in run_checks(ctx)}
    assert not any(i.startswith("HR-ADCS") for i in ids)
    assert "HR-HYG-005" not in ids and "HR-HYG-004" in ids


def test_failing_check_becomes_warning(result, monkeypatch):
    from houndreport import checks

    def boom(ctx):
        raise RuntimeError("kaboom")
        yield  # pragma: no cover

    load_checks()
    monkeypatch.setitem(checks.REGISTRY, "boom", checks.RegisteredCheck("boom", boom))
    ctx = AnalysisContext(result.graph, result.tier0, Options(), result.reference_time)
    ctx.paths = result.paths
    out = run_checks(ctx)
    assert out and any("boom" in w and "kaboom" in w for w in ctx.warnings)


@pytest.mark.parametrize("os_name,expected", [
    ("Windows Server 2012 R2 Standard", True),
    ("Windows Server 2008 R2 Enterprise", True),
    ("Windows 7 Professional", True),
    ("Windows 10 Pro", True),
    ("Windows 10 Enterprise LTSC", False),
    ("Windows 11 Enterprise", False),
    ("Windows Server 2016 Standard", False),
    ("Windows Server 2022 Datacenter", False),
    (None, False),
])
def test_unsupported_os(os_name, expected):
    assert is_unsupported_os(os_name) is expected
