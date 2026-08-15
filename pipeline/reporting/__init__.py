"""Reporting: daily digests and export to external formats."""

from pipeline.reporting.daily_summary import build_summary, render_markdown

# ``digest`` is deliberately *not* re-exported here. It is run as
# ``python -m pipeline.reporting.digest`` from cron, and importing it in the
# package __init__ makes runpy emit a RuntimeWarning on every run — daily noise
# in cron mail. Import it directly: ``from pipeline.reporting.digest import ...``.
from pipeline.reporting.export import (
    export_blocklist,
    export_events_csv,
    export_events_jsonl,
    export_misp,
    export_stix,
)

__all__ = [
    "build_summary",
    "render_markdown",
    "export_events_csv",
    "export_events_jsonl",
    "export_stix",
    "export_misp",
    "export_blocklist",
]
