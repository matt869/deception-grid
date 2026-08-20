"""Static analysis of captured artefacts.

Nothing in this package executes a sample, and nothing fetches a URL found
inside one. It reads bytes that are already on disk and reports what they are.
That constraint is the whole design: see :mod:`pipeline.analysis.static`.

``static`` is deliberately *not* re-exported here, for the same reason
``pipeline.reporting`` leaves out ``digest``: it is run as
``python -m pipeline.analysis.static``, and importing it in the package
``__init__`` makes runpy emit a RuntimeWarning on every invocation. Import it
directly — ``from pipeline.analysis.static import analyze``.
"""
