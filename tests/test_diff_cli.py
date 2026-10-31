import copy
import json

import pytest
from click.testing import CliRunner

from houndreport.cli import main
from houndreport.diff import diff_documents, render_diff_html, worst_new_severity
from houndreport.pipeline import build_document


@pytest.fixture(scope="module")
def base_doc(result):
    return build_document(result)


def _changed(doc):
    new = copy.deepcopy(doc)
    new["findings"] = [f for f in new["findings"] if f["id"] != "HR-HYG-001"]  # resolved
    kerb = next(f for f in new["findings"] if f["id"] == "HR-KERB-002")
    kerb["affected"] = [a for a in kerb["affected"] if a["name"] != "SVC_SQL@CORP.LOCAL"]
    kerb["affected"].append({"key": "S-1-NEW", "name": "SVC_NEW@CORP.LOCAL", "type": "User",
                             "objectid": "S-1-NEW", "severity": "Medium", "details": {}})
    new["findings"].append({"id": "HR-TEST-001", "title": "Brand new", "severity": "Critical",
                            "affected": [{"key": "k", "name": "X", "type": "User", "objectid": "k",
                                          "severity": "Critical", "details": {}}]})
    new["risk"] = dict(new["risk"], score=new["risk"]["score"] - 5)
    return new


def test_diff_classification(base_doc):
    d = diff_documents(base_doc, _changed(base_doc))
    assert [f["id"] for f in d["new_findings"]] == ["HR-TEST-001"]
    assert [f["id"] for f in d["resolved_findings"]] == ["HR-HYG-001"]
    kerb = next(p for p in d["persisting_findings"] if p["id"] == "HR-KERB-002")
    assert [a["name"] for a in kerb["new_objects"]] == ["SVC_NEW@CORP.LOCAL"]
    assert [a["name"] for a in kerb["resolved_objects"]] == ["SVC_SQL@CORP.LOCAL"]
    assert kerb["persisting_objects"] == 1
    assert d["risk_delta"] == -5
    assert worst_new_severity(d) == 4
    html = render_diff_html(d)
    assert "HR-TEST-001" in html and "Content-Security-Policy" in html


def test_identical_reports(base_doc):
    d = diff_documents(base_doc, copy.deepcopy(base_doc))
    assert d["summary"]["new"] == d["summary"]["resolved"] == 0
    assert worst_new_severity(d) == -1


def test_cli_analyze_and_diff(corp_zip, tmp_path):
    runner = CliRunner()
    r1 = runner.invoke(main, ["analyze", str(corp_zip), "-o", str(tmp_path / "a"), "--client-name", "ACME",
                              "--top-paths", "3", "--stale-days", "30"])
    assert r1.exit_code == 0, r1.output
    assert "HR-PATH-001" in r1.output
    doc = json.loads((tmp_path / "a" / "findings.json").read_text(encoding="utf-8"))
    assert doc["client"] == "ACME" and doc["options"] == {"stale_days": 30, "top_paths": 3}

    changed = _changed(doc)
    (tmp_path / "b.json").write_text(json.dumps(changed), encoding="utf-8")
    r2 = runner.invoke(main, ["diff", str(tmp_path / "a" / "findings.json"), str(tmp_path / "b.json"),
                              "--html", str(tmp_path / "diff.html"), "--json", str(tmp_path / "diff.json"), "-v"])
    assert r2.exit_code == 0, r2.output
    assert "NEW (1)" in r2.output and "RESOLVED (1)" in r2.output and "+ SVC_NEW@CORP.LOCAL" in r2.output
    assert (tmp_path / "diff.html").is_file()
    assert json.loads((tmp_path / "diff.json").read_text(encoding="utf-8"))["summary"]["new"] == 1

    r3 = runner.invoke(main, ["diff", str(tmp_path / "a" / "findings.json"), str(tmp_path / "b.json"),
                              "--fail-on-new", "high"])
    assert r3.exit_code == 2


def test_cli_redact_and_as_of(corp_dir, tmp_path):
    r = CliRunner().invoke(main, ["analyze", str(corp_dir), "-o", str(tmp_path), "--redact",
                                  "--redact-salt", "x", "--as-of", "2027-01-01", "-q"])
    assert r.exit_code == 0, r.output
    doc = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert doc["redacted"] and doc["reference_date"] == "2027-01-01"
    stale = next(f for f in doc["findings"] if f["id"] == "HR-HYG-002")
    assert stale["affected_count"] >= 8  # everything is stale a year later


def test_cli_rejects_empty_input(tmp_path):
    r = CliRunner().invoke(main, ["analyze", str(tmp_path), "-o", str(tmp_path / "o")])
    assert r.exit_code != 0 and "no usable SharpHound data" in r.output


def test_cli_diff_rejects_non_report(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    r = CliRunner().invoke(main, ["diff", str(bad), str(bad)])
    assert r.exit_code != 0 and "not a houndreport findings.json" in r.output


def test_list_checks():
    r = CliRunner().invoke(main, ["list-checks"])
    assert r.exit_code == 0 and "HR-ADCS-ESC1" in r.output
