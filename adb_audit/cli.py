"""python -m adb_audit.cli EXPORT"""

from __future__ import annotations

import argparse
import sys

from .model import ExportError, load_export
from .rules import exit_code, run_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="autonomous-db-config-audit",
        description="Audit an offline export of OCI Autonomous Database instances for exposure and hygiene gaps.",
    )
    p.add_argument("export", help="path to the JSON export")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        databases = load_export(args.export)
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    findings = run_all(databases)
    n_public = sum(1 for d in databases if d.is_public())
    print(
        f"Autonomous database audit - {len(databases)} database(s) ({n_public} with public access), "
        f"{len(findings)} finding(s)"
    )
    for x in findings:
        print(f"[{x.severity:6s}] {x.rule} database={x.database}")
        print(f"         {x.detail}")
    code = exit_code(findings)
    print({0: "RESULT: clean", 1: "RESULT: warnings only", 2: "RESULT: HIGH findings present"}[code])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
