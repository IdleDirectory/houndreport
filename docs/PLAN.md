# houndreport — design plan

Offline analysis of SharpHound CE / BloodHound CE collector output. No network access at
runtime, no database: everything is computed in memory from the JSON files.

## Pipeline

```
input (.zip | dir | .json)
  └─ loader.load()            → RawData      (per-type item lists, file inventory, warnings)
      └─ graph.build_graph()  → ADGraph      (networkx DiGraph + ADObject index)
          └─ tier0.compute_tier0() → Tier0   (privileged principals + Tier 0 infrastructure)
              ├─ attackpaths.compute_attack_paths() → PathResult
              ├─ checks.run_checks(ctx)            → [Finding]
              ├─ stats.hygiene_stats(ctx)          → dict
              └─ scoring.risk_score()              → dict
                  └─ pipeline.build_document()     → doc (plain dict; optionally redacted)
                      ├─ report.html   (Jinja2, self-contained)
                      ├─ findings.json (doc as JSON)
                      └─ csv/<FINDING-ID>.csv
```

`houndreport diff old.json new.json` compares two `findings.json` documents by finding ID
and, inside each finding, by each affected object's stable `key`.

## Data model (`houndreport/model.py`)

| Type | Fields | Notes |
|------|--------|-------|
| `ADObject` | `oid`, `kind`, `name`, `domain`, `props`, `placeholder` | `oid` = upper-cased ObjectIdentifier (SID/GUID). `placeholder` = referenced but not collected (e.g. a well-known SID seen only in an ACE). |
| graph edge | `src → dst`, attr `rels: {kind: {inherited, via[]}}` | One DiGraph edge per pair; multiple relationship kinds are merged into `rels`. Direction follows BloodHound: *attacker → target*. |
| `Severity` | Critical / High / Medium / Low / Info | `.rank` for sorting. |
| `Affected` | `key`, `name`, `objectid`, `type`, `severity?`, `details{}` | `key` is stable across runs (objectid, or a composite like `principal\|target\|right`). |
| `Finding` | `id`, `title`, `severity`, `category`, `description`, `remediation`, `controls[]`, `references[]`, `affected[]` | `id` is stable (`HR-KERB-001`...) so reports can be diffed. Controls are NIST SP 800-171 r2 IDs; CMMC L2 IDs are derived (`3.1.5` → `AC.L2-3.1.5`). |
| `Hop` / `AttackPath` | hop: `src`, `dst`, `kind`, `explanation`; path: `source`, `target`, `impact`, `hops[]`, `key` | `impact` = enabled users who inherit the source's access. |

### Edge kinds

* Membership: `MemberOf` (from `Members` and `PrimaryGroupSID`)
* Host access: `AdminTo`, `CanRDP`, `CanPSRemote`, `ExecuteDCOM` (computer collections and OU/domain `GPOChanges`)
* Sessions: `HasSession` (computer → user)
* ACEs: the raw `RightName` (`GenericAll`, `WriteDacl`, `GetChangesAll`, `Enroll`...), with `inherited`
* Delegation: `AllowedToDelegate` (principal → target), `AllowedToAct` (principal → computer, RBCD)
* Structure: `Contains`, `GPLink`, `HasSIDHistory`, ADCS `PublishedTo`, `HostsCAService`
* Derived: `DCSync` (principal holds GetChanges + GetChangesAll on a domain)

## Tier 0

Seeds: domain objects, Domain Admins (512), Enterprise Admins (519), Schema Admins (518),
Domain Controllers (516), Key Admins (526/527), Administrators and the operator groups
(S-1-5-32-544/548/549/550/551), Enterprise DCs (S-1-5-9), krbtgt (502), built-in
Administrator (500), DC computer objects, and every DCSync principal. Expanded by transitive
group membership, except broad groups (Domain Users, Authenticated Users...) which are
reported instead of absorbed. *Targets* additionally include OUs holding DCs and GPOs linked to
Tier 0 containers.

## Checks (pluggable)

`houndreport.checks.check(name, ids=...)` registers `fn(ctx) -> Iterable[Finding]`.
Built-ins live in `houndreport/checks/`; third parties can register through the
`houndreport.checks` entry-point group.

| Module | Finding IDs |
|--------|-------------|
| kerberos | HR-KERB-001 privileged Kerberoastable, HR-KERB-002 other Kerberoastable, HR-KERB-003 AS-REP roastable |
| delegation | HR-DELEG-001 unconstrained, HR-DELEG-002 constrained, HR-DELEG-003 RBCD |
| acl | HR-ACL-001 non-default DCSync, HR-ACL-002 dangerous ACEs over Tier 0 |
| access | HR-ACCESS-001 broad groups local admin, HR-ACCESS-002 privileged sessions on non-Tier 0 hosts, HR-ACCESS-003 broad group nested in Tier 0 |
| hygiene | HR-HYG-001 orphaned adminCount, HR-HYG-002 stale accounts, HR-HYG-003 password never expires, HR-HYG-004 unsupported OS, HR-HYG-005 no LAPS |
| adcs | HR-ADCS-ESC1..ESC4 |
| paths | HR-PATH-001 attack paths to Tier 0 |

## Attack paths

One multi-source BFS on the reversed traversable-edge graph from all Tier 0 targets gives every
node's shortest distance and next hop. Sources are enabled non-Tier 0 users and non-Tier 0
groups. Paths that differ only in leading `MemberOf` hops are de-duplicated (keeping the source
with the largest impact), then ranked by hop count and impact.

## Redaction

`--redact` replaces user names, host names, domain names and domain SIDs with salted SHA-256
tokens (`USER-1a2b3c4d`, `HOST-...`, `DOM-...`) across every output. The same salt
(`--redact-salt` / `HOUNDREPORT_REDACT_SALT`) yields the same tokens, so redacted reports
remain diffable. Static text (titles, descriptions, remediation) is never rewritten.

## Implementation order

1. model, sids, loader → tests
2. graph, tier0 → tests
3. context + checks → tests
4. attack paths → tests
5. stats, scoring, document, redaction, HTML/JSON/CSV → tests
6. diff + CLI → tests, README
