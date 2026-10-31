from conftest import DSID, sid

from houndreport.graph import build_graph
from houndreport.loader import RawData
from houndreport.tier0 import compute_tier0


def rels(graph, src, dst):
    return set(graph.g[src][dst]["rels"]) if graph.g.has_edge(src, dst) else set()


def test_edges_built(result):
    g = result.graph
    assert "MemberOf" in rels(g, sid(1102), sid(1200))  # Members
    assert "MemberOf" in rels(g, sid(1102), sid(513))  # PrimaryGroupSID
    assert "AdminTo" in rels(g, sid(1200), sid(1301))
    assert "HasSession" in rels(g, sid(1301), sid(1105))
    assert "AllowedToAct" in rels(g, sid(1302), sid(1303))
    assert "AllowedToDelegate" in rels(g, sid(1109), sid(1000))
    assert "ForceChangePassword" in rels(g, sid(1104), sid(1107))
    assert "Contains" in rels(g, DSID, "0A1B2C3D-0000-4000-8000-000000000001")
    assert "GPLink" in rels(g, "6AC1786C-016F-11D2-945F-00C04FB984F9", "0A1B2C3D-0000-4000-8000-000000000001")
    assert "PublishedTo" in rels(g, "0A1B2C3D-0000-4000-8000-0000000000D1", "0A1B2C3D-0000-4000-8000-0000000000C1")


def test_gpo_changes_grant_local_admin(result):
    g = result.graph
    rel = g.g[sid(1200)][sid(1302)]["rels"]["AdminTo"]
    assert rel["via"] and "WORKSTATIONS@CORP.LOCAL" in rel["via"][0]


def test_dcsync_derived(result):
    g = result.graph
    holders = {u for u, _, _, _ in g.edges("DCSync")}
    assert sid(1108) in holders
    assert sid(498) not in holders  # GetChanges only


def test_sid_resolution(result):
    g = result.graph
    assert g.name("CORP.LOCAL-S-1-5-11") == "AUTHENTICATED USERS@CORP.LOCAL"
    assert g.name(sid(498)) == "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.LOCAL"
    assert g.obj(sid(498)).placeholder


def test_tier0_membership(result):
    t0, g = result.tier0, result.graph
    expected = {"ADMINISTRATOR@CORP.LOCAL", "JANE@CORP.LOCAL", "SVC_BACKUP@CORP.LOCAL", "KRBTGT@CORP.LOCAL",
                "DC01.CORP.LOCAL", "CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL", "SVC_SYNC@CORP.LOCAL"}
    assert expected <= {g.name(o) for o in t0.principals}
    for user in ("ALICE", "CAROL", "SVC_SQL", "OLD_ADMIN"):
        assert f"{user}@CORP.LOCAL" not in {g.name(o) for o in t0.principals}
    assert sid(1108) not in t0.base  # Tier 0 only because of DCSync
    assert t0.dcs == {sid(1000)}


def test_tier0_targets_include_dc_ou_and_linked_gpos(result):
    names = {result.graph.name(o) for o in result.tier0.targets - result.tier0.principals}
    assert names == {"DOMAIN CONTROLLERS@CORP.LOCAL", "DEFAULT DOMAIN CONTROLLERS POLICY@CORP.LOCAL",
                     "DEFAULT DOMAIN POLICY@CORP.LOCAL"}


def test_broad_group_nested_in_tier0_is_reported_not_absorbed():
    d = "S-1-5-21-9-9-9"
    raw = RawData(by_type={
        "groups": [
            {"ObjectIdentifier": f"{d}-512", "Properties": {"name": "DOMAIN ADMINS@X.LOCAL"},
             "Members": [{"ObjectIdentifier": f"{d}-513", "ObjectType": "Group"}]},
            {"ObjectIdentifier": f"{d}-513", "Properties": {"name": "DOMAIN USERS@X.LOCAL"}},
        ],
        "users": [{"ObjectIdentifier": f"{d}-1100", "PrimaryGroupSID": f"{d}-513",
                   "Properties": {"name": "U@X.LOCAL", "enabled": True}}],
    })
    g = build_graph(raw)
    t0 = compute_tier0(g)
    assert f"{d}-1100" not in t0.principals
    assert t0.broad_nested == [(f"{d}-513", f"{d}-512")]
