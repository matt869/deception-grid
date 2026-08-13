"""Processing pipeline: enrichment, detection and reporting.

Import order matters here only in that ``pipeline.enrichment`` must stay
importable without the optional ``geoip2`` dependency — the honeypot's writer
thread imports it on every start.
"""

from pipeline.detection import evaluate_rules, load_rules, run_detection, score_attacker
from pipeline.enrichment import enrich_event, enrich_ip

__all__ = [
    "enrich_event",
    "enrich_ip",
    "load_rules",
    "evaluate_rules",
    "run_detection",
    "score_attacker",
]
