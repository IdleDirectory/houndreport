from __future__ import annotations

import sys
import zipfile
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
CORP = FIXTURES / "corp"
DSID = "S-1-5-21-1000-2000-3000"

sys.path.insert(0, str(FIXTURES))


def sid(rid: int) -> str:
    return f"{DSID}-{rid}"


@pytest.fixture(scope="session")
def corp_dir() -> Path:
    return CORP


@pytest.fixture(scope="session")
def corp_zip(tmp_path_factory) -> Path:
    path = tmp_path_factory.mktemp("zip") / "20260101_BloodHound.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for f in sorted(CORP.iterdir()):
            zf.write(f, f.name)
    return path


@pytest.fixture(scope="session")
def result():
    from houndreport.context import Options
    from houndreport.pipeline import analyze
    return analyze(CORP, Options())


@pytest.fixture(scope="session")
def findings(result):
    return {f.id: f for f in result.findings}


def names(finding) -> set[str]:
    return {a.name for a in finding.affected}
