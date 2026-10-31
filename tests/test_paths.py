from conftest import sid


def by_source(result):
    return {p.source_name: p for p in result.paths.paths}


def test_paths_found(result):
    paths = by_source(result)
    assert set(paths) == {"DOMAIN USERS@CORP.LOCAL", "CAROL@CORP.LOCAL", "SVC_WEB@CORP.LOCAL", "HELPDESK@CORP.LOCAL"}


def test_helpdesk_session_path(result):
    p = by_source(result)["HELPDESK@CORP.LOCAL"]
    assert [h.kind for h in p.hops] == ["AdminTo", "HasSession"]
    assert p.target == sid(1105)
    assert all(h.explanation for h in p.hops)
    assert "WS01.CORP.LOCAL" in p.hops[0].explanation


def test_leading_membership_deduplicated(result):
    # ALICE reaches Tier 0 only through HELPDESK and DOMAIN USERS, so she has no path of her own.
    assert "ALICE@CORP.LOCAL" not in by_source(result)


def test_ranking_and_impact(result):
    paths = result.paths.paths
    assert [len(p.hops) for p in paths] == sorted(len(p.hops) for p in paths)
    assert paths[0].source_name == "DOMAIN USERS@CORP.LOCAL"
    assert paths[0].impact == result.paths.enabled_users == 6


def test_users_with_path(result):
    assert result.paths.users_with_path == 6
    assert result.paths.users_with_path_pct == 100.0


def test_paths_never_start_in_tier0(result):
    for p in result.paths.paths:
        assert p.source not in result.tier0.principals
        assert p.target in result.tier0.targets
        assert all(h.src not in result.tier0.targets for h in p.hops)
