# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Detection engine (Phase 2): Sigma-subset rule evaluation over NormalizedEvents."""
from .engine import DetectionEngine, Rule, flatten_event, load_rules, match_rule

__all__ = ["DetectionEngine", "Rule", "flatten_event", "load_rules", "match_rule"]
