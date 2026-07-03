#!/usr/bin/env python3
"""Print the LogOcean detection-coverage report and (optionally) write ATT&CK
Navigator layers — the CI-publishable coverage artifact for the detection-coverage
programme (see docs/DETECTION_COVERAGE_ROADMAP.md).

    python scripts/coverage_report.py [--rules DIR] [--out DIR]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import coverage                                    # noqa: E402
from app.detection.correlation import load_correlation_rules  # noqa: E402
from app.detection.engine import load_rules                 # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="LogOcean detection-coverage report")
    ap.add_argument("--rules", default=str(ROOT / "rules"), help="rules directory")
    ap.add_argument("--out", default=None, help="directory to write Navigator layers + report JSON")
    args = ap.parse_args(argv)

    det = load_rules(args.rules)
    corr = load_correlation_rules(args.rules)
    rep = coverage.coverage_report(det, corr)
    a, at = rep["attack"], rep["atlas"]

    print(f"Rules: {rep['rules']['total']} "
          f"({rep['rules']['detection']} event + {rep['rules']['correlation']} correlation)")
    print(f"ATT&CK Enterprise techniques covered: {a['enterprise_covered']} (~{a['enterprise_pct']}%)")
    print(f"ATT&CK ICS techniques covered:        {a['ics_covered']} (~{a['ics_pct']}%)")
    print(f"Fidelity (covered techniques): high={a['fidelity']['high']} "
          f"medium={a['fidelity']['medium']} hunt={a['fidelity']['hunt']}")
    print(f"ATLAS techniques covered: {at['covered']}/{at['total']} ({at['coverage_pct']}%)")
    print()
    print(f"{'Tactic':<24}{'rules':>6}  covered techniques")
    for t in a["tactics"]:
        print(f"{t['title']:<24}{t['rules']:>6}  {', '.join(t['enabled_techniques']) or '-'}")
    if a["untagged_rules"]:
        print(f"\n{a['untagged_rules']} rule(s) carry no ATT&CK/ATLAS tag.")

    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "attack_coverage_enterprise.json").write_text(
            json.dumps(coverage.navigator_layer(det + corr, "enterprise-attack"), indent=2))
        (out / "attack_coverage_ics.json").write_text(
            json.dumps(coverage.navigator_layer(det + corr, "ics-attack"), indent=2))
        (out / "coverage_report.json").write_text(json.dumps(rep, indent=2))
        print(f"\nWrote Navigator layers + report to {out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
