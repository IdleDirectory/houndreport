import json

import make_fixture
import pytest

from houndreport.loader import load


def test_fixture_matches_generator(tmp_path, corp_dir):
    make_fixture.write(tmp_path)
    for f in sorted(tmp_path.iterdir()):
        assert (corp_dir / f.name).read_bytes() == f.read_bytes(), f"{f.name} is stale; run make_fixture.py"


def test_load_directory(corp_dir):
    raw = load(corp_dir)
    assert set(raw.by_type) == {"users", "groups", "computers", "domains", "ous", "containers",
                                "gpos", "certtemplates", "enterprisecas"}
    versions = {f["type"]: f["version"] for f in raw.files}
    assert versions["users"] == 5 and versions["computers"] == 6
    assert len(raw.by_type["users"]) == 12


def test_unknown_and_broken_files_warn(corp_dir):
    raw = load(corp_dir)
    assert any("widgets" in w and "unknown data type" in w for w in raw.warnings)
    assert any("broken.json" in w and "not valid JSON" in w for w in raw.warnings)


def test_zip_equals_directory(corp_dir, corp_zip):
    a, b = load(corp_dir), load(corp_zip)
    assert a.by_type == b.by_type
    assert a.warnings == b.warnings


def test_legacy_version_skipped_and_newer_parsed(tmp_path):
    (tmp_path / "old_users.json").write_text(json.dumps(
        {"data": [{"ObjectIdentifier": "S-1-5-21-1-2-3-1000"}], "meta": {"type": "users", "count": 1, "version": 4}}))
    (tmp_path / "x_groups.json").write_text(json.dumps(
        {"data": [{"ObjectIdentifier": "S-1-5-21-1-2-3-512"}], "meta": {"type": "groups", "count": 1, "version": 7}}))
    raw = load(tmp_path)
    assert "users" not in raw.by_type
    assert len(raw.by_type["groups"]) == 1
    assert any("legacy" in w for w in raw.warnings)
    assert any("newer than tested" in w for w in raw.warnings)


def test_type_inferred_from_filename_and_bom(tmp_path):
    body = json.dumps({"data": [{"ObjectIdentifier": "S-1-5-21-1-2-3-1000"}], "meta": {"version": 6}})
    (tmp_path / "20260101_computers.json").write_bytes(b"\xef\xbb\xbf" + body.encode())
    raw = load(tmp_path)
    assert len(raw.by_type["computers"]) == 1


def test_count_mismatch_warns(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps({"data": [], "meta": {"type": "users", "count": 3, "version": 6}}))
    raw = load(tmp_path)
    assert any("meta.count is 3" in w for w in raw.warnings)


def test_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load(tmp_path / "nope.zip")
