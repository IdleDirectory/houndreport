import csv
import json
import re

import pytest

from houndreport.pipeline import build_document
from houndreport.redact import Redactor
from houndreport.report import render_html, write_outputs

SENSITIVE = ["ALICE", "CAROL", "JANE", "SVC_SQL", "SVC_BACKUP", "WS01", "APP01", "DC01", "CORP.LOCAL",
             "sql01.corp.local", "1000-2000-3000"]


@pytest.fixture(scope="module")
def outputs(result, tmp_path_factory):
    out = tmp_path_factory.mktemp("out")
    doc = build_document(result, client_name="Example <Corp> & Co")
    write_outputs(doc, out)
    return out, doc


def test_files_written(outputs):
    out, doc = outputs
    assert (out / "report.html").is_file()
    assert (out / "findings.json").is_file()
    csvs = {p.stem for p in (out / "csv").glob("*.csv")}
    assert csvs == {f["id"] for f in doc["findings"]}


def test_findings_json_schema(outputs):
    out, _ = outputs
    doc = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert doc["schema_version"] == 1
    assert doc["risk"]["rating"] in {"Low", "Moderate", "High", "Critical"}
    assert 0 <= doc["risk"]["score"] <= 100
    for f in doc["findings"]:
        assert {"id", "title", "severity", "description", "remediation", "controls", "affected"} <= set(f)
        keys = [a["key"] for a in f["affected"]]
        assert len(keys) == len(set(keys)), f"duplicate affected keys in {f['id']}"
    assert doc["attack_paths"] and doc["attack_paths"][0]["hops"]


def test_html_is_self_contained(outputs):
    html = (outputs[0] / "report.html").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert not re.search(r"""\b(src|srcset)\s*=\s*["']?(https?:)?//""", html, re.I)
    assert not re.search(r"<link\b", html, re.I)
    assert not re.search(r"url\(\s*['\"]?(https?:)?//", html, re.I)
    assert "@import" not in html
    assert "<svg" in html and "path-svg" in html


def test_html_content_and_escaping(outputs):
    html = (outputs[0] / "report.html").read_text(encoding="utf-8")
    assert "Example &lt;Corp&gt; &amp; Co" in html
    assert "<Corp>" not in html
    for fid in ("HR-ACL-002", "HR-PATH-001", "HR-ADCS-ESC1"):
        assert f'id="f-{fid}"' in html
    assert "prefers-color-scheme: dark" in html and "@media print" in html
    assert "AC.L2-3.1.5" in html


def test_csv_contents(outputs):
    out, _ = outputs
    with (out / "csv" / "HR-ACL-002.csv").open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert {r["principal"] for r in rows} == {"DOMAIN USERS@CORP.LOCAL", "CAROL@CORP.LOCAL"}
    assert all(r["finding_id"] == "HR-ACL-002" for r in rows)


def test_csv_formula_injection_neutralised(tmp_path):
    doc_finding = {"id": "HR-X", "affected": [{"key": "k", "name": "=cmd|' /C calc'!A0", "type": "User",
                                               "objectid": "S-1", "severity": None, "details": {"n": 3}}]}
    from houndreport.report import write_csv
    write_csv(doc_finding, tmp_path / "x.csv")
    text = (tmp_path / "x.csv").read_text(encoding="utf-8-sig")
    assert "'=cmd" in text


def test_top_paths_limits_svg(result):
    doc = build_document(result)
    doc["options"]["top_paths"] = 2
    assert render_html(doc).count('class="path-svg"') == 2


def test_redaction_removes_identifiers(result, tmp_path):
    doc = build_document(result, client_name="Client", redactor=Redactor(result.graph, "salt"))
    write_outputs(doc, tmp_path)
    blobs = [p.read_text(encoding="utf-8-sig") for p in tmp_path.rglob("*") if p.is_file()]
    for blob in blobs:
        for token in SENSITIVE:
            assert token.lower() not in blob.lower(), f"{token} leaked"
    assert doc["redacted"] is True
    # Group names survive (minus their domain); static text is untouched.
    assert any(a["name"].startswith("DOMAIN USERS@DOM-") for p in doc["findings"] for a in p["affected"]
               if p["id"] == "HR-PATH-001")
    assert doc["findings"][0]["description"] == next(f for f in build_document(result)["findings"])["description"]


def test_redaction_stable_per_salt(result):
    a = Redactor(result.graph, "one").text("ALICE@CORP.LOCAL on WS01.CORP.LOCAL")
    b = Redactor(result.graph, "one").text("alice@corp.local on ws01.corp.local")
    c = Redactor(result.graph, "two").text("ALICE@CORP.LOCAL on WS01.CORP.LOCAL")
    assert a == b != c
    assert re.fullmatch(r"USER-[0-9a-f]{8}@DOM-[0-9a-f]{8} on HOST-[0-9a-f]{8}\.DOM-[0-9a-f]{8}", a)
