"""Reporting: daily digests and export to external formats.

Neither ``digest`` nor ``export`` is re-exported here. Both are run as
``python -m pipeline.reporting.<name>`` — from cron and by hand — and importing
a module in the package ``__init__`` makes runpy emit a RuntimeWarning about it
already being in ``sys.modules`` on every single run. In cron that is daily
noise in the mail; at a terminal it is a warning above output people are trying
to read.

Import them directly::

    from pipeline.reporting.export import export_stix
    from pipeline.reporting import export      # or the module, as the API does
"""

from pipeline.reporting.daily_summary import build_summary, render_markdown

__all__ = [
    "build_summary",
    "render_markdown",
]
