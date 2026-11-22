# oci-autonomous-db-config-audit

**Category: custom portfolio tool.** The OOTB built-in-services project in this pair is
`oci-ootb-compartment-quota-check`.

## The problem

An Autonomous Database can sit on the public internet ("Secure access from everywhere"),
behind an ACL, or on a private endpoint - and mutual TLS is only *required* if someone
selects it; per the OCI docs the default allows both TLS and mTLS. For a production
database these defaults deserve a second look, but nothing in the platform asks. This tool
audits an offline JSON export of ADB instances and flags the gaps worth a human review.

## The rules

| Rule | Severity | Fires when |
| ---- | -------- | ---------- |
| ADB001 | HIGH | A **prod-labeled** database records access type `everywhere` - a production database reachable from the public internet (mTLS is enforced there, but the exposure itself warrants review). |
| ADB002 | MEDIUM | A database with **public network access** (`everywhere` or `allowed-ips`) records `mtls_required: false` - per the docs that default allows plain TLS connections without a client wallet. |
| ADB003 | MEDIUM | A **prod-labeled** database records `auto_scaling: false` - fixed capacity through traffic peaks; a deliberate choice sometimes, but worth confirming. |
| ADB004 | LOW | No description and no tags recorded - the database is hard to trace to an owner or purpose. |

Exit code: `2` on any HIGH, `1` on MEDIUM/LOW only, `0` when clean.

## Run it

```bash
python -m adb_audit.cli samples/adb_messy.json   # exits 2, all 4 rules fire
python -m adb_audit.cli samples/adb_clean.json   # exits 0
python -m unittest discover -s tests -v          # 17 tests, stdlib only
```

## Honest limits

- **Offline audit**: the JSON export is synthetic; nothing calls the OCI API.
- Findings are review prompts describing what the export records - a public endpoint or
  fixed capacity can be a deliberate design; ADB003 is not a claim that anything is broken.
- Access-type and mTLS semantics are from the Autonomous Database docs as of Nov 2026
  ("Secure access from everywhere" forces mTLS; TLS+mTLS is the default when ACLs or a
  private endpoint are configured). Verify current behavior before acting.
- "prod" labeling is read from the export; an unlabeled production database is invisible
  to ADB001/ADB003.
- No live tenancy was touched.

## Project status

Built as a daily portfolio project. 17 unit tests, green locally and in CI. Free tier
only; no live cloud calls, no spend.
