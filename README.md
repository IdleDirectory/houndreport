# houndreport

Offline analysis reports for **BloodHound CE / SharpHound CE** collector output.

`houndreport` reads a SharpHound `.zip` (or a folder of its JSON files), builds an in-memory
graph of the directory, identifies Tier 0, runs a set of pluggable checks and computes attack
paths. It writes a single self-contained HTML report, a diffable `findings.json`, and one CSV
per finding. No BloodHound server, database or network access is needed. The HTML report
makes no network requests and ships a Content-Security-Policy that blocks them.

## Install

Requires Python 3.11+.

```bash
pip install .
```

For development (includes pytest):

```bash
pip install -e ".[dev]"
```

## Usage

```bash
houndreport analyze 20261031_BloodHound.zip -o out/ --client-name "Example Corp"
```

| Option | Default | Meaning |
|--------|---------|---------|
| `-o, --output DIR` | `houndreport-out` | Output directory |
| `--stale-days N` | `90` | Days without logon before an enabled account is stale |
| `--top-paths N` | `10` | Attack paths drawn in the HTML report (all are in `findings.json`) |
| `--redact` | off | Replace user, host and domain names and domain SIDs with hashed tokens |
| `--redact-salt S` | `""` (env `HOUNDREPORT_REDACT_SALT`) | Secret salt for `--redact`; reuse it to keep redacted reports diffable |
| `--client-name TEXT` | | Name shown in the report header |
| `--as-of YYYY-MM-DD` | newest logon in data | Reference date for staleness |
| `--skip-check NAME_OR_ID` | | Skip a check module (`adcs`) or a finding (`HR-HYG-005`); repeatable |

Input can be a `.zip`, a directory (searched recursively for `*.json`), or one `.json` file.
SharpHound CE `meta.version` 5 and 6 are supported. Unknown types, invalid JSON and legacy
(pre-CE) files are skipped with a warning; newer versions are parsed best-effort.

### Compare two runs

```bash
houndreport diff before/findings.json after/findings.json --html diff.html
```

This prints new, resolved and persisting findings, plus the objects added to or removed from
each persisting finding (`-v` lists them). `--json FILE` writes the comparison as JSON, and
`--fail-on-new high` exits with status 2 if anything new at High or above appeared, which is
useful in CI.

### Outputs

```
out/
├── report.html      # executive summary, risk score, findings, attack paths, hygiene, Tier 0 inventory
├── findings.json    # everything in the report, schema_version 1
└── csv/
    ├── HR-ACL-002.csv
    └── ...
```

`report.html` has light and dark themes (follows the OS, with a toggle) and print styles that
expand every finding. Findings are sortable and filterable by severity and text. Attack paths
are drawn as inline SVG with a hop-by-hop explanation. An example generated from the synthetic
test fixture is in [examples/sample/report.html](examples/sample/report.html).

## Findings

| ID | Title | Severity |
|----|-------|----------|
| HR-KERB-001 | Kerberoastable privileged accounts | Critical (Tier 0) / High (adminCount) |
| HR-KERB-002 | Kerberoastable user accounts | Medium |
| HR-KERB-003 | AS-REP roastable accounts | High / Critical if privileged |
| HR-DELEG-001 | Unconstrained delegation on non-DC accounts | Critical |
| HR-DELEG-002 | Constrained delegation | Medium → Critical (protocol transition to Tier 0) |
| HR-DELEG-003 | Resource-based constrained delegation | Medium → Critical (on Tier 0) |
| HR-ACL-001 | Non-default principals with DCSync rights | Critical |
| HR-ACL-002 | Dangerous ACEs over Tier 0 held by non-Tier 0 principals | Critical |
| HR-ACCESS-001 | Domain Users / Authenticated Users / Everyone local admin | High / Critical on Tier 0 |
| HR-ACCESS-002 | Tier 0 sessions on non-Tier 0 hosts | High |
| HR-ACCESS-003 | Broad group nested in a Tier 0 group | Critical |
| HR-HYG-001 | Orphaned adminCount | Low |
| HR-HYG-002 | Stale enabled accounts | Medium |
| HR-HYG-003 | Password never expires | Medium / High if privileged |
| HR-HYG-004 | Unsupported operating systems | High / Critical on DCs |
| HR-HYG-005 | Computers without LAPS | Medium |
| HR-ADCS-ESC1..4 | ADCS template misconfigurations (only when certtemplates data exists) | High / Critical if open to broad groups |
| HR-PATH-001 | Attack paths to Tier 0 | High / Critical |

Each finding has a description, remediation guidance, and NIST SP 800-171 r2 control IDs
with the matching CMMC Level 2 practice (`3.1.5` → `AC.L2-3.1.5`). Finding IDs are stable,
and each affected object has a stable `key` (object ID, or e.g. `principal|target|right` for an
ACE), which is what `diff` compares.

### Tier 0

Seeds: domain objects; Domain Admins, Enterprise Admins, Schema Admins, Domain Controllers,
Key Admins, Enterprise Key Admins; built-in Administrators, Account/Server/Print/Backup
Operators; Enterprise Domain Controllers; krbtgt and the built-in Administrator; DC computer
objects; and every principal that can DCSync (GetChanges + GetChangesAll). These are expanded
through nested group membership. Broad groups such as Domain Users are never absorbed into
Tier 0; nesting one is reported as HR-ACCESS-003. OUs that contain DCs and GPOs linked to the
domain or those OUs are treated as Tier 0 *targets* for ACL and path analysis.

### Attack paths

Edges followed: MemberOf, AdminTo, HasSession, CanRDP, CanPSRemote, ExecuteDCOM, delegation
(AllowedToDelegate, AllowedToAct, AddAllowedToAct), HasSIDHistory, DCSync, Contains, GPLink
and the abusable ACL rights (GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns,
ForceChangePassword, AddMember, AddSelf, AllExtendedRights, AddKeyCredentialLink, WriteSPN,
WriteAccountRestrictions, ReadLAPSPassword, SyncLAPSPassword, ReadGMSAPassword, WriteGPLink).
One reverse BFS from all Tier 0 targets finds the shortest path from every enabled non-Tier 0
user and non-Tier 0 group. Paths that differ only in leading group memberships are merged under
the source with the widest membership. The ranking puts shorter paths first, then paths that
affect more users.

### Risk score

Each finding contributes its severity weight (Critical 30, High 12, Medium 4, Low 1), scaled by
`1 + log10(affected)`. The total maps to 0-100 with `100 * (1 - e^(-total/150))`. Ratings:
Low < 25 ≤ Moderate < 50 ≤ High < 75 ≤ Critical.

## Redaction

`--redact` rewrites every output (HTML, JSON, CSV): user names become `USER-xxxxxxxx`, hosts
`HOST-xxxxxxxx`, domains `DOM-xxxxxxxx`, and domain SIDs `S-1-5-21-REDACTED-xxxxxxxx` (RIDs are
kept). Tokens are salted SHA-256 prefixes, so the same salt gives the same tokens across runs.
**Use a secret `--redact-salt`**: without one, short names can be recovered by brute force.
Group, OU, GPO and certificate template names are kept, with their domain part redacted.
Review custom group names before sharing.

## Writing a check

A check is a function that takes the analysis context and yields `Finding` objects. Findings
with no affected objects are dropped automatically.

```python
from houndreport.checks import check
from houndreport.model import Finding, Severity

@check("sidhistory", ids=("ACME-SIDH-001",))
def sid_history(ctx):
    affected = [ctx.affected(src, Severity.HIGH, target=ctx.graph.name(dst))
                for src, dst, _, _ in ctx.graph.edges("HasSIDHistory")]
    yield Finding(id="ACME-SIDH-001", title="Accounts with SID history", severity=Severity.HIGH,
                  description="...", remediation="...", affected=affected, controls=["3.1.5"])
```

Expose it from another package through an entry point:

```toml
[project.entry-points."houndreport.checks"]
sidhistory = "acme_checks.sidhistory"   # a module (its @check decorators register) or a callable
```

`ctx` provides `graph` (an `ADGraph` wrapping a networkx `DiGraph`, with `objects`, `edges(kind)`,
`in_edges`, `out_edges`, `groups_of`, `members_of`), `tier0`, `options`, `paths`, `broad_closure`,
and helpers such as `is_tier0`, `is_privileged`, `days_since` and `affected`. A check that raises
becomes a warning in the report and does not stop the run. `houndreport list-checks` shows
what is registered.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The tests use an invented `CORP.LOCAL` data set in `tests/fixtures/corp/`, generated by
`tests/fixtures/make_fixture.py`. Its docstring lists the planted weaknesses, and a test
fails if the JSON drifts from the generator. Design notes are in [docs/PLAN.md](docs/PLAN.md).

## Limitations

- Sessions and local group data reflect the moment of collection. A missing session is not
  proof that an account never logs on there.
- Stale-account age is measured against the newest logon timestamp in the data, not today's
  date, unless `--as-of` is given. `lastLogonTimestamp` can lag by up to 14 days.
- ESC1-ESC4 use the template and CA data SharpHound collects. CA-level settings (e.g. ESC6/ESC8)
  and Enrollment Agent restrictions are not evaluated.
- "Unsupported OS" cannot see Extended Security Updates enrolment.
