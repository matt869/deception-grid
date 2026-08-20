"""Tests for the benchmark harness.

Timings are not asserted on — a number that depends on the machine is not a
test, and pinning one produces a suite that fails on a busy CI runner for no
reason. What is asserted is everything around the numbers: that the harness
isolates itself from the real database, that it reports what it claims to
report, and that the arithmetic turning samples into percentiles is right.

The isolation test is the one that matters. ``tools/benchmark.py`` seeds tens
of thousands of synthetic events, and a run that leaked into a live sensor's
store would poison the capture the sensor exists to produce — irreversibly,
because synthetic rows are indistinguishable from real ones after the fact.
"""

from __future__ import annotations

import json
import os

import pytest

from tools import benchmark

# --------------------------------------------------------------------------- #
# Isolation
# --------------------------------------------------------------------------- #


class TestTemporaryDatabase:
    def test_points_database_url_at_a_temp_file(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "sqlite:///production.db")
        with benchmark.temp_database() as tmp:
            active = os.environ["DATABASE_URL"]
            assert "production.db" not in active
            assert str(tmp.as_posix()) in active

    def test_restores_the_previous_url(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "sqlite:///production.db")
        with benchmark.temp_database():
            pass
        assert os.environ["DATABASE_URL"] == "sqlite:///production.db"

    def test_restores_even_when_the_body_raises(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "sqlite:///production.db")
        with pytest.raises(RuntimeError), benchmark.temp_database():
            raise RuntimeError("benchmark blew up")
        assert os.environ["DATABASE_URL"] == "sqlite:///production.db"

    def test_unsets_the_variable_if_there_was_none(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        with benchmark.temp_database():
            assert "DATABASE_URL" in os.environ
        assert "DATABASE_URL" not in os.environ

    def test_the_temp_database_has_a_schema(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        with benchmark.temp_database():
            from storage.db import session_scope
            from storage.models import Event

            with session_scope() as db:
                assert db.query(Event).count() == 0


# --------------------------------------------------------------------------- #
# Result arithmetic
# --------------------------------------------------------------------------- #


class TestResult:
    def test_rate_is_operations_over_seconds(self):
        assert benchmark.Result("x", 100, 2.0).per_second == 50.0

    def test_zero_duration_does_not_divide_by_zero(self):
        assert benchmark.Result("x", 10, 0.0).per_second == float("inf")

    def test_percentiles_are_reported_in_milliseconds(self):
        samples = [i / 1000 for i in range(1, 101)]  # 1ms .. 100ms
        pct = benchmark.Result("x", 100, 5.05, samples=samples).percentiles
        assert pct["p50"] == pytest.approx(51, abs=1)
        assert pct["p95"] == pytest.approx(96, abs=1)

    def test_percentiles_are_absent_without_samples(self):
        assert benchmark.Result("x", 1, 1.0).percentiles == {}

    def test_single_sample_does_not_index_out_of_range(self):
        pct = benchmark.Result("x", 1, 0.5, samples=[0.5]).percentiles
        assert pct["p50"] == pct["p99"] == 500.0

    def test_as_dict_includes_latency_only_when_measured(self):
        assert "latency_ms" not in benchmark.Result("x", 1, 1.0).as_dict()
        assert "latency_ms" in benchmark.Result("x", 1, 1.0, samples=[0.1]).as_dict()

    def test_as_dict_carries_the_note(self):
        assert benchmark.Result("x", 1, 1.0, note="5 dropped").as_dict()["note"] == "5 dropped"


# --------------------------------------------------------------------------- #
# Synthetic data
# --------------------------------------------------------------------------- #


class TestSyntheticData:
    def test_generated_events_use_public_addresses(self):
        # Documentation ranges are classified private by ipaddress, so seeding
        # with them would benchmark enrichment's early return instead of the
        # work it actually does.
        import ipaddress

        for ip in benchmark.BENCH_IPS[:20]:
            assert not ipaddress.ip_address(ip).is_private

    def test_event_dicts_are_insertable(self, db):
        import random

        from storage.models import Event, utcnow

        rng = random.Random(1)
        db.add(Event(**benchmark.make_event_dict(rng, utcnow())))
        db.commit()
        assert db.query(Event).count() == 1

    def test_seeding_is_deterministic_for_a_given_seed(self):
        import random

        from storage.models import utcnow

        ts = utcnow()
        first = benchmark.make_event_dict(random.Random(4), ts)
        second = benchmark.make_event_dict(random.Random(4), ts)
        assert first["src_ip"] == second["src_ip"]
        assert first["command"] == second["command"]

    def test_seed_events_writes_the_requested_count(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        with benchmark.temp_database():
            from storage.db import session_scope
            from storage.models import Event

            assert benchmark.seed_events(120) == 120
            with session_scope() as db:
                assert db.query(Event).count() == 120


# --------------------------------------------------------------------------- #
# Running
# --------------------------------------------------------------------------- #


class TestRun:
    def test_analyse_only_needs_no_seeded_data(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        results = benchmark.run(["analyse"], events=10, ingest_events=5, repeats=1, analyse_count=3)
        assert [r.name for r in results] == ["analyse"]
        assert results[0].n == 3

    def test_query_benchmarks_seed_first(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        results = benchmark.run(["query"], events=50, ingest_events=5, repeats=2, analyse_count=1)
        names = [r.name for r in results]
        assert names[0] == "seed"
        assert any(n.startswith("query:") for n in names)

    def test_query_results_carry_latency_samples(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        results = benchmark.run(["query"], events=50, ingest_events=5, repeats=3, analyse_count=1)
        for result in (r for r in results if r.name.startswith("query:")):
            assert len(result.samples) == 3
            assert result.percentiles

    def test_ingest_reports_what_was_written(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        results = benchmark.run(["ingest"], events=10, ingest_events=25, repeats=1, analyse_count=1)
        assert {r.name for r in results} == {"ingest", "ingest+enrich"}
        for result in results:
            assert "25 written" in result.note

    def test_leaves_no_database_url_behind(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        benchmark.run(["analyse"], events=1, ingest_events=1, repeats=1, analyse_count=1)
        assert "DATABASE_URL" not in os.environ


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


class TestCli:
    def test_only_selects_a_subset(self, monkeypatch, capsys):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        assert benchmark.main(["--only", "analyse", "--analyse", "2"]) == 0
        out = capsys.readouterr().out
        assert "analyse" in out
        assert "query:summary" not in out

    def test_unknown_benchmark_is_a_usage_error(self):
        with pytest.raises(SystemExit):
            benchmark.main(["--only", "nonsense"])

    def test_json_output_is_written_and_parseable(self, monkeypatch, tmp_path, capsys):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        out_file = tmp_path / "bench.json"
        benchmark.main(["--only", "analyse", "--analyse", "2", "--json", str(out_file)])
        payload = json.loads(out_file.read_text(encoding="utf-8"))
        assert payload["results"][0]["name"] == "analyse"
        assert "python" in payload

    def test_table_renders_without_samples(self):
        table = benchmark.render_table([benchmark.Result("solo", 5, 1.0, unit="things")])
        assert "solo" in table
        assert "things/s" in table
