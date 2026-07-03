"""Rule-linter: structural quality gates on every shipped detection rule.

Runs in CI (plain pytest) so a malformed or untagged rule fails the build. Parses
the raw YAML (not the loaded Rule) so it catches typos the loader would silently
coerce (e.g. a bad ``fidelity`` value).
"""
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

_LEVELS = {"informational", "low", "medium", "high", "critical"}
_FIDELITY = {"high", "medium", "hunt"}


def _rule_docs():
    for path in sorted(list(RULES_DIR.glob("*.yml")) + list(RULES_DIR.glob("*.yaml"))):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if isinstance(doc, dict) and (doc.get("detection") or doc.get("correlation")):
                yield path.name, doc


def test_rule_ids_are_unique_and_present():
    ids = [d.get("id") for _, d in _rule_docs()]
    assert all(ids), "every rule needs an 'id'"
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate rule ids: {dupes}"


def test_every_rule_meets_the_schema():
    problems: list[str] = []
    for name, d in _rule_docs():
        rid = d.get("id") or name
        if not str(d.get("title") or "").strip():
            problems.append(f"{rid}: missing title")
        if not str(d.get("description") or "").strip():
            problems.append(f"{rid}: missing description")
        level = str(d.get("level") or "").lower()
        if not level or level not in _LEVELS:
            problems.append(f"{rid}: level must be one of {sorted(_LEVELS)} (got {level!r})")
        tags = [str(t).lower() for t in (d.get("tags") or [])]
        if not any(t.startswith("attack.") or t.startswith("atlas.") for t in tags):
            problems.append(f"{rid}: needs at least one attack.* or atlas.* tag")
        fid = d.get("fidelity")
        if fid is not None and str(fid).lower() not in _FIDELITY:
            problems.append(f"{rid}: fidelity must be one of {sorted(_FIDELITY)} (got {fid!r})")
    assert not problems, "rule quality issues:\n  " + "\n  ".join(problems)
