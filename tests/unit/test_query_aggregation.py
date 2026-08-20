"""Tests for the aggregation paths behind the dashboard's slowest endpoints.

Both of these functions were rewritten after ``tools/benchmark.py`` measured
them, and both rewrites are the kind that can be quietly wrong:

* :func:`events_timeseries` now groups in SQL when it recognises the dialect
  and falls back to Python otherwise. Two code paths producing the same chart
  is a promise, so the central test here runs both against the same data and
  asserts the results are identical — not merely similar. The first version of
  the SQL path passed a smoke test while grouping every row into its own
  bucket, because SQLAlchemy renders ``/`` as float division and the index came
  back fractional. Only an equality check against the old path catches that.
* :func:`summary_stats` folded six scans into one conditional aggregation.
  ``SUM`` over zero matching rows returns NULL rather than 0, so the empty
  window gets its own test.
"""

from __future__ import annotations

import datetime as dt

import pytest

from storage import queries
from storage.models import EventType, utcnow


@pytest.fixture
def python_bucketing(monkeypatch):
    """Force the Python fallback by hiding the SQL expression."""
    monkeypatch.setattr(queries, "_bucket_index_expr", lambda *a, **k: None)


@pytest.fixture
def spread(db, make_event):
    """Events spread across several hours, services and severities."""
    base = utcnow() - dt.timedelta(hours=6)
    events = []
    for hour in range(6):
        for i, service in enumerate(["ssh", "http", "redis"]):
            for n in range(hour + i + 1):  # uneven counts per bucket
                events.append(
                    make_event(
                        service=service,
                        event_type=EventType.AUTH_ATTEMPT.value
                        if n % 2
                        else EventType.COMMAND.value,
                        ts=base + dt.timedelta(hours=hour, minutes=n),
                    )
                )
    db.add_all(events)
    db.commit()
    return len(events)


# --------------------------------------------------------------------------- #
# The two bucketing paths must agree
# --------------------------------------------------------------------------- #


class TestBucketingPathsAgree:
    @pytest.mark.parametrize("bucket", ["15m", "1h", "6h", "1d"])
    def test_identical_output_for_every_bucket_size(self, db, spread, monkeypatch, bucket):
        fast = queries.events_timeseries(db, since_hours=12, bucket=bucket)
        monkeypatch.setattr(queries, "_bucket_index_expr", lambda *a, **k: None)
        slow = queries.events_timeseries(db, since_hours=12, bucket=bucket)
        assert fast == slow

    @pytest.mark.parametrize("by", ["service", "severity", "event_type", "none"])
    def test_identical_output_for_every_dimension(self, db, spread, monkeypatch, by):
        fast = queries.events_timeseries(db, since_hours=12, by=by)
        monkeypatch.setattr(queries, "_bucket_index_expr", lambda *a, **k: None)
        slow = queries.events_timeseries(db, since_hours=12, by=by)
        assert fast == slow

    def test_identical_on_an_empty_database(self, db, monkeypatch):
        fast = queries.events_timeseries(db, since_hours=6)
        monkeypatch.setattr(queries, "_bucket_index_expr", lambda *a, **k: None)
        slow = queries.events_timeseries(db, since_hours=6)
        assert fast == slow

    def test_identical_with_an_unbounded_window(self, db, spread, monkeypatch):
        fast = queries.events_timeseries(db, since_hours=None)
        monkeypatch.setattr(queries, "_bucket_index_expr", lambda *a, **k: None)
        slow = queries.events_timeseries(db, since_hours=None)
        assert fast == slow


class TestBucketingCorrectness:
    def test_every_event_is_counted_exactly_once(self, db, spread):
        result = queries.events_timeseries(db, since_hours=12)
        assert sum(point["total"] for point in result["points"]) == spread

    def test_the_fallback_counts_the_same_total(self, db, spread, python_bucketing):
        result = queries.events_timeseries(db, since_hours=12)
        assert sum(point["total"] for point in result["points"]) == spread

    def test_buckets_are_aligned_to_the_interval(self, db, spread):
        for point in queries.events_timeseries(db, since_hours=12, bucket="1h")["points"]:
            ts = dt.datetime.fromisoformat(point["ts"])
            assert (ts.minute, ts.second, ts.microsecond) == (0, 0, 0)

    def test_quiet_buckets_are_zero_filled_not_skipped(self, db, make_event):
        # A gap must draw as zero, not as a line connecting across it.
        now = utcnow()
        db.add_all(
            [
                make_event(ts=now - dt.timedelta(hours=5)),
                make_event(ts=now - dt.timedelta(minutes=1)),
            ]
        )
        db.commit()
        points = queries.events_timeseries(db, since_hours=6, bucket="1h")["points"]
        assert any(p["total"] == 0 for p in points)

    def test_series_names_are_reported(self, db, spread):
        result = queries.events_timeseries(db, since_hours=12, by="service")
        assert set(result["series"]) == {"ssh", "http", "redis"}

    def test_unknown_bucket_is_rejected(self, db):
        with pytest.raises(ValueError, match="unknown bucket"):
            queries.events_timeseries(db, bucket="3s")

    def test_unknown_dimension_is_rejected(self, db):
        with pytest.raises(ValueError, match="cannot split by"):
            queries.events_timeseries(db, by="src_ip")


class TestBucketExpression:
    def test_sqlite_is_recognised(self, db):
        assert queries._bucket_index_expr(db, dt.timedelta(hours=1)) is not None

    def test_unknown_dialect_degrades_rather_than_guessing(self, db, monkeypatch):
        # Returning a wrong expression would silently misplace every point, so
        # anything unrecognised must fall through to the Python path.
        class FakeBind:
            dialect = type("D", (), {"name": "oracle"})()

        monkeypatch.setattr(db, "get_bind", lambda: FakeBind())
        assert queries._bucket_index_expr(db, dt.timedelta(hours=1)) is None

    def test_index_matches_python_flooring(self, db, make_event):
        # The SQL index and _floor must be the same arithmetic, or the two
        # paths cannot agree.
        from sqlalchemy import select

        ts = utcnow() - dt.timedelta(hours=2, minutes=37)
        db.add(make_event(ts=ts))
        db.commit()

        delta = dt.timedelta(hours=1)
        expr = queries._bucket_index_expr(db, delta)
        index = db.execute(select(expr)).scalar_one()
        assert queries._EPOCH + int(index) * delta == queries._floor(ts, delta)


# --------------------------------------------------------------------------- #
# summary_stats, after folding six scans into one
# --------------------------------------------------------------------------- #


class TestSummaryStats:
    def test_empty_window_reports_zeros_not_nulls(self, db):
        # SUM over no rows is NULL. Every counter must still be an int.
        stats = queries.summary_stats(db, since_hours=24)
        for key in ("total_events", "auth_attempts", "commands_run", "unique_attackers"):
            assert stats[key] == 0, key
            assert isinstance(stats[key], int), key

    def test_counts_match_the_data(self, db, make_event):
        db.add_all(
            [
                make_event(src_ip="45.33.32.1", event_type=EventType.AUTH_ATTEMPT.value),
                make_event(src_ip="45.33.32.1", event_type=EventType.AUTH_ATTEMPT.value),
                make_event(src_ip="45.33.32.2", event_type=EventType.COMMAND.value),
                make_event(src_ip="45.33.32.2", event_type=EventType.CONNECT.value),
            ]
        )
        db.commit()
        stats = queries.summary_stats(db, since_hours=24)
        assert stats["total_events"] == 4
        assert stats["auth_attempts"] == 2
        assert stats["commands_run"] == 1
        assert stats["unique_attackers"] == 2

    def test_unique_credential_pairs_counts_distinct_combinations(self, db, make_event):
        db.add_all(
            [
                make_event(
                    event_type=EventType.AUTH_ATTEMPT.value, username="root", password="123"
                ),
                make_event(
                    event_type=EventType.AUTH_ATTEMPT.value, username="root", password="123"
                ),
                make_event(
                    event_type=EventType.AUTH_ATTEMPT.value, username="root", password="456"
                ),
                make_event(
                    event_type=EventType.AUTH_ATTEMPT.value, username="admin", password="123"
                ),
            ]
        )
        db.commit()
        assert queries.summary_stats(db, since_hours=24)["unique_credential_pairs"] == 3

    def test_credential_pairs_ignore_non_auth_events(self, db, make_event):
        # A command event carrying a stale username must not invent a pair.
        db.add_all(
            [
                make_event(
                    event_type=EventType.AUTH_ATTEMPT.value, username="root", password="123"
                ),
                make_event(event_type=EventType.COMMAND.value, username="other", password="zzz"),
            ]
        )
        db.commit()
        assert queries.summary_stats(db, since_hours=24)["unique_credential_pairs"] == 1

    def test_window_excludes_older_events(self, db, make_event):
        db.add_all(
            [
                make_event(ts=utcnow() - dt.timedelta(hours=48)),
                make_event(ts=utcnow() - dt.timedelta(minutes=5)),
            ]
        )
        db.commit()
        assert queries.summary_stats(db, since_hours=24)["total_events"] == 1

    def test_unbounded_window_counts_everything(self, db, make_event):
        db.add_all(
            [
                make_event(ts=utcnow() - dt.timedelta(days=90)),
                make_event(ts=utcnow()),
            ]
        )
        db.commit()
        assert queries.summary_stats(db, since_hours=None)["total_events"] == 2

    def test_unique_countries_ignores_unenriched_events(self, db, make_event):
        db.add_all(
            [
                make_event(country="NL"),
                make_event(country="NL"),
                make_event(country="DE"),
                make_event(country=None),
            ]
        )
        db.commit()
        assert queries.summary_stats(db, since_hours=24)["unique_countries"] == 2
