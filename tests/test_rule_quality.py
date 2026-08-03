# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Rule-linter: structural quality gates on every shipped detection rule.

Runs in CI (plain pytest) so a malformed or untagged rule fails the build. Parses
the raw YAML (not the loaded Rule) so it catches typos the loader would silently
coerce (e.g. a bad ``fidelity`` value).
"""
from pathlib import Path

import yaml

# The one loader helper the linter borrows: a `datamodels:` check has to coerce the
# YAML value exactly the way `rule_from_dict` will, or it would lint a different rule
# than the engine runs.
from app.detection.engine import as_str_list

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


def _datamodels(doc: dict) -> list[str]:
    """A rule's CIM binding, coerced as the loader coerces it (str or list)."""
    return as_str_list(doc.get("datamodels") or doc.get("datamodel"))


def test_every_rule_datamodel_binding_resolves_against_the_registry():
    """A `datamodels:` typo must fail CI rather than go quietly dead in production.

    The engine deliberately disables a rule whose binding names no model -- a typo
    must never fall through to match-all -- and a disabled rule is invisible: it just
    never fires, which looks exactly like "there was nothing to detect". This is the
    only place that difference is observable, so it is checked here.

    Correlation rules are rejected outright: they filter in SQL via `db.correlate`
    and never reach `match_rule`, so a binding on one would silently do nothing.
    """
    from app.cim.registry import get_registry

    reg = get_registry()
    known = sorted(set(reg.tags) | {n.lower() for n in reg.names})
    problems: list[str] = []
    for name, d in _rule_docs():
        rid = d.get("id") or name
        names = _datamodels(d)
        if names and d.get("correlation"):
            problems.append(f"{rid}: correlation rules never reach match_rule, so a "
                            "`datamodels:` binding on one has no effect")
        for n in names:
            if reg.by_name(n) is None:
                problems.append(f"{rid}: unknown CIM data model {n!r} "
                                f"(known: {', '.join(known)})")
    assert not problems, "rule datamodel issues:\n  " + "\n  ".join(problems)


def test_the_shipped_pack_binds_rules_to_data_models():
    """At least one shipped rule actually uses the binding.

    Without this the feature can be reverted rule-by-rule and stay green, and the
    roadmap's exit criterion -- a detection binds to a data model, not a vendor --
    would be true of the engine but of nothing anyone runs.
    """
    bound = {d.get("id"): _datamodels(d) for _, d in _rule_docs() if _datamodels(d)}
    assert bound, "no shipped rule binds to a CIM data model"
