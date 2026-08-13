"""Detection: declarative rules and attacker scoring."""

from pipeline.detection.rules import (
    Rule,
    RuleError,
    evaluate_rules,
    load_rules,
    run_detection,
)
from pipeline.detection.scoring import classify, explain, score_attacker

__all__ = [
    "Rule",
    "RuleError",
    "load_rules",
    "evaluate_rules",
    "run_detection",
    "score_attacker",
    "classify",
    "explain",
]
