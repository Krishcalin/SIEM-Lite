#!/usr/bin/env python3
# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Import community SigmaHQ rules into LogOcean (Phase 1 of the detection-coverage
programme; see docs/DETECTION_COVERAGE_ROADMAP.md).

Point it at a clone of https://github.com/SigmaHQ/sigma and it translates every
rule it can run on our telemetry into `rules/imported/`, then prints a
loaded-vs-skipped report (skips are bucketed by reason, so nothing dies silently).
Restart LogOcean (or reload rules) and the /coverage scoreboard reflects the jump.

    git clone https://github.com/SigmaHQ/sigma
    python scripts/import_sigma.py --src sigma/rules            # dry-run report
    python scripts/import_sigma.py --src sigma/rules --write    # write rules/imported/

Imported rules keep the original Sigma id / author + a source reference (DRL).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import sigma_import                       # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Import SigmaHQ rules into LogOcean")
    ap.add_argument("--src", required=True, help="directory of SigmaHQ .yml rules")
    ap.add_argument("--out", default=str(ROOT / "rules" / "imported"),
                    help="output directory (default: rules/imported)")
    ap.add_argument("--write", action="store_true", help="write rules (default: dry-run)")
    ap.add_argument("--top", type=int, default=12, help="how many skip reasons to show")
    args = ap.parse_args(argv)

    if not Path(args.src).is_dir():
        print(f"error: --src {args.src!r} is not a directory", file=sys.stderr)
        return 2

    rules, report = sigma_import.translate_dir(args.src)
    techniques = {t.split(".", 1)[1].upper() for r in rules for t in r["tags"]
                  if str(t).lower().startswith("attack.") and _is_technique(t)}

    print(f"Scanned {report['scanned']} Sigma rules")
    print(f"  imported : {report['imported']}  ({len(techniques)} distinct ATT&CK techniques)")
    print(f"  skipped  : {report['skipped']}")
    if report["duplicates"]:
        print(f"  duplicates dropped: {report['duplicates']}")
    print("\nTop skip reasons:")
    for reason, n in list(report["reasons"].items())[:args.top]:
        print(f"  {n:>5}  {reason}")

    if args.write:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for old in out.glob("sigma-*.yml"):
            old.unlink()
        for r in rules:
            (out / f"{r['id']}.yml").write_text(sigma_import.dump_rule(r), encoding="utf-8")
        print(f"\nWrote {len(rules)} rules to {out}/  (restart LogOcean to load them)")
    else:
        print("\n(dry-run; pass --write to emit rules/imported/)")
    return 0


def _is_technique(tag: str) -> bool:
    import re
    return bool(re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", str(tag).lower()))


if __name__ == "__main__":
    raise SystemExit(main())
