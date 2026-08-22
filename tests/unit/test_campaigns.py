"""Unit tests for behavioural campaign clustering.

The failure mode this module has to be protected from is not "misses a
campaign" — it is "puts the entire internet in one cluster". Every source in a
honeypot capture touches SSH and tries `root`, so a similarity function that
counts ambient behaviour produces one giant group that says nothing while
looking like a result. Several tests here exist purely to pin that down: two
unrelated scanners must *not* cluster, and sources with no discriminative
behaviour must be dropped rather than joined.

The other property worth guarding is that a grouping can be argued with. Every
campaign reports the credentials, paths and artefacts its members actually
share, so an analyst can look at the evidence and disagree.
"""

from __future__ import annotations

import datetime as dt

import pytest

from pipeline.analysis import campaigns
from pipeline.analysis.campaigns import Fingerprint, cluster, jaccard, similarity
from storage.models import EventType, utcnow


def fp(ip: str, **kwargs) -> Fingerprint:
    """A fingerprint with set-valued facets given as plain iterables."""
    for key in ("usernames", "credentials", "paths", "services", "tags", "payloads"):
        if key in kwargs:
            kwargs[key] = frozenset(kwargs[key])
    kwargs.setdefault("event_count", 10)
    return Fingerprint(src_ip=ip, **kwargs)


# --------------------------------------------------------------------------- #
# Similarity
# --------------------------------------------------------------------------- #


class TestJaccard:
    def test_identical_sets(self):
        assert jaccard(frozenset("abc"), frozenset("abc")) == 1.0

    def test_disjoint_sets(self):
        assert jaccard(frozenset("abc"), frozenset("xyz")) == 0.0

    def test_partial_overlap(self):
        assert jaccard(frozenset("abcd"), frozenset("abxy")) == pytest.approx(2 / 6)

    def test_empty_sets_share_nothing_not_everything(self):
        # The degenerate case that would otherwise make every sparse
        # fingerprint look identical to every other.
        assert jaccard(frozenset(), frozenset()) == 0.0
        assert jaccard(frozenset("a"), frozenset()) == 0.0


class TestSimilarity:
    def test_identical_behaviour_scores_one(self):
        a = fp("45.33.32.1", credentials=["root:admin"], paths=["/x"], payloads=["deadbeef"])
        assert similarity(a, fp("45.33.32.2", **_facets(a))) == pytest.approx(1.0)

    def test_completely_different_behaviour_scores_zero(self):
        a = fp("45.33.32.1", credentials=["root:admin"], paths=["/a"])
        b = fp("45.33.32.2", credentials=["oracle:oracle"], paths=["/b"])
        assert similarity(a, b) == 0.0

    def test_shared_service_alone_is_nearly_worthless(self):
        # Everything on the internet touches SSH. If this scores high, the
        # clusterer groups the entire capture.
        a = fp("45.33.32.1", services=["ssh"], credentials=["root:a"])
        b = fp("45.33.32.2", services=["ssh"], credentials=["admin:b"])
        assert similarity(a, b) < 0.2

    def test_shared_payload_dominates(self):
        # The same bytes from two addresses is close to conclusive.
        a = fp("45.33.32.1", payloads=["sha-1"], credentials=["root:a"], services=["ssh"])
        b = fp("45.33.32.2", payloads=["sha-1"], credentials=["admin:b"], services=["ssh"])
        assert similarity(a, b) > 0.45

    def test_shared_credentials_outweigh_shared_services(self):
        creds = fp("45.33.32.1", credentials=["root:hunter2"], services=["ssh"])
        creds_match = fp("45.33.32.2", credentials=["root:hunter2"], services=["telnet"])
        svc_match = fp("45.33.32.3", credentials=["oracle:x"], services=["ssh"])
        assert similarity(creds, creds_match) > similarity(creds, svc_match)

    def test_facets_neither_side_has_are_ignored(self):
        # A source with no recorded paths must not be penalised for it,
        # otherwise sparse fingerprints never cluster with anything.
        a = fp("45.33.32.1", credentials=["root:a"])
        b = fp("45.33.32.2", credentials=["root:a"])
        assert similarity(a, b) == pytest.approx(1.0)

    def test_similarity_is_symmetric(self):
        a = fp("45.33.32.1", credentials=["root:a", "x:y"], paths=["/p"])
        b = fp("45.33.32.2", credentials=["root:a"], paths=["/p", "/q"])
        assert similarity(a, b) == similarity(b, a)

    def test_score_stays_in_range(self):
        a = fp("45.33.32.1", credentials=["a:b"], paths=["/p"], payloads=["s"], tags=["t"])
        b = fp("45.33.32.2", credentials=["a:b"], paths=["/q"], payloads=["s"], tags=["u"])
        assert 0.0 <= similarity(a, b) <= 1.0


def _facets(f: Fingerprint) -> dict:
    return {
        "usernames": f.usernames,
        "credentials": f.credentials,
        "paths": f.paths,
        "services": f.services,
        "tags": f.tags,
        "payloads": f.payloads,
    }


# --------------------------------------------------------------------------- #
# Clustering
# --------------------------------------------------------------------------- #


class TestCluster:
    def test_two_matching_sources_form_a_campaign(self):
        result = cluster(
            [
                fp("45.33.32.1", credentials=["root:hunter2"], paths=["/shell.php"]),
                fp("45.33.32.2", credentials=["root:hunter2"], paths=["/shell.php"]),
            ]
        )
        assert len(result) == 1
        assert result[0].members == ["45.33.32.1", "45.33.32.2"]

    def test_unrelated_sources_do_not_cluster(self):
        # The headline failure mode: these share only "ssh" and must stay apart.
        result = cluster(
            [
                fp("45.33.32.1", services=["ssh"], credentials=["root:a"], paths=["/one"]),
                fp("45.33.32.2", services=["ssh"], credentials=["oracle:b"], paths=["/two"]),
            ]
        )
        assert result == []

    def test_a_lone_source_is_not_a_campaign(self):
        assert cluster([fp("45.33.32.1", credentials=["root:a"])]) == []

    def test_transitive_membership(self):
        # A~B and B~C puts all three together even if A and C never overlap
        # directly — an operator rotating credentials across a range.
        result = cluster(
            [
                fp("45.33.32.1", credentials=["a:1", "b:2"]),
                fp("45.33.32.2", credentials=["b:2", "c:3"]),
                fp("45.33.32.3", credentials=["c:3", "d:4"]),
            ],
            threshold=0.3,
        )
        assert len(result) == 1
        assert result[0].size == 3

    def test_separate_campaigns_stay_separate(self):
        result = cluster(
            [
                fp("45.33.32.1", credentials=["root:hunter2"], paths=["/a"]),
                fp("45.33.32.2", credentials=["root:hunter2"], paths=["/a"]),
                fp("93.184.216.1", credentials=["oracle:oracle"], paths=["/b"]),
                fp("93.184.216.2", credentials=["oracle:oracle"], paths=["/b"]),
            ]
        )
        assert len(result) == 2
        assert all(c.size == 2 for c in result)

    def test_sources_with_no_behaviour_are_dropped(self):
        # Connect-and-leave probes: clustering these would produce one giant
        # group of every port scanner on the internet.
        result = cluster(
            [
                fp("45.33.32.1", services=["ssh"]),
                fp("45.33.32.2", services=["ssh"]),
                fp("45.33.32.3", services=["telnet"]),
            ]
        )
        assert result == []

    def test_higher_threshold_splits_a_loose_group(self):
        pair = [
            fp("45.33.32.1", credentials=["a:1", "b:2"], paths=["/x"]),
            fp("45.33.32.2", credentials=["a:1", "c:3"], paths=["/y"]),
        ]
        assert cluster(pair, threshold=0.2)
        assert cluster(pair, threshold=0.95) == []

    def test_shared_payload_alone_can_form_a_campaign(self):
        result = cluster(
            [
                fp("45.33.32.1", payloads=["sha-aaa"], credentials=["x:1"]),
                fp("93.184.216.1", payloads=["sha-aaa"], credentials=["y:2"]),
            ],
            threshold=0.4,
        )
        assert len(result) == 1

    def test_min_size_is_respected(self):
        members = [
            fp("45.33.32.1", credentials=["a:1"]),
            fp("45.33.32.2", credentials=["a:1"]),
        ]
        assert cluster(members, min_size=3) == []

    def test_empty_input(self):
        assert cluster([]) == []

    def test_largest_campaign_comes_first(self):
        result = cluster(
            [
                fp("45.33.32.1", credentials=["a:1"]),
                fp("45.33.32.2", credentials=["a:1"]),
                fp("45.33.32.3", credentials=["a:1"]),
                fp("93.184.216.1", credentials=["z:9"]),
                fp("93.184.216.2", credentials=["z:9"]),
            ]
        )
        assert [c.size for c in result] == [3, 2]

    def test_clustering_is_deterministic(self):
        members = [
            fp("45.33.32.1", credentials=["a:1"], paths=["/x"]),
            fp("45.33.32.2", credentials=["a:1"], paths=["/x"]),
            fp("93.184.216.1", credentials=["z:9"], paths=["/y"]),
            fp("93.184.216.2", credentials=["z:9"], paths=["/y"]),
        ]
        first = [c.members for c in cluster(members)]
        second = [c.members for c in cluster(list(reversed(members)))]
        assert sorted(first) == sorted(second)


class TestCampaignSummary:
    def test_reports_the_evidence_for_the_grouping(self):
        # A grouping an analyst cannot inspect is a grouping they cannot argue
        # with, which makes it useless as evidence.
        result = cluster(
            [
                fp("45.33.32.1", credentials=["root:hunter2"], paths=["/shell.php"]),
                fp("45.33.32.2", credentials=["root:hunter2"], paths=["/shell.php"]),
            ]
        )
        campaign = result[0]
        assert campaign.shared_credentials == ["root:hunter2"]
        assert campaign.shared_paths == ["/shell.php"]

    def test_only_facets_common_to_every_member_are_reported_shared(self):
        result = cluster(
            [
                fp("45.33.32.1", credentials=["a:1", "only-mine:x"]),
                fp("45.33.32.2", credentials=["a:1"]),
            ],
            threshold=0.3,
        )
        assert result[0].shared_credentials == ["a:1"]

    def test_aggregates_events_asns_and_countries(self):
        result = cluster(
            [
                fp("45.33.32.1", credentials=["a:1"], asn=63949, country="NL", event_count=100),
                fp("45.33.32.2", credentials=["a:1"], asn=14061, country="DE", event_count=50),
            ]
        )
        campaign = result[0]
        assert campaign.event_count == 150
        assert campaign.asns == [14061, 63949]
        assert campaign.countries == ["DE", "NL"]

    def test_spans_the_members_time_range(self):
        now = utcnow()
        result = cluster(
            [
                fp(
                    "45.33.32.1",
                    credentials=["a:1"],
                    first_seen=now - dt.timedelta(days=5),
                    last_seen=now - dt.timedelta(days=4),
                ),
                fp(
                    "45.33.32.2",
                    credentials=["a:1"],
                    first_seen=now - dt.timedelta(days=1),
                    last_seen=now,
                ),
            ]
        )
        assert result[0].first_seen == now - dt.timedelta(days=5)
        assert result[0].last_seen == now

    def test_cohesion_is_reported(self):
        result = cluster(
            [
                fp("45.33.32.1", credentials=["a:1"], paths=["/x"]),
                fp("45.33.32.2", credentials=["a:1"], paths=["/x"]),
            ]
        )
        assert result[0].cohesion == pytest.approx(1.0)

    def test_as_dict_is_json_serialisable(self):
        import json

        result = cluster(
            [
                fp("45.33.32.1", credentials=["a:1"], first_seen=utcnow(), last_seen=utcnow()),
                fp("45.33.32.2", credentials=["a:1"], first_seen=utcnow(), last_seen=utcnow()),
            ]
        )
        assert json.loads(json.dumps(result[0].as_dict()))["size"] == 2


# --------------------------------------------------------------------------- #
# Database path
# --------------------------------------------------------------------------- #


@pytest.fixture
def two_campaigns(db, make_event):
    """Four sources: two sharing credentials, two sharing a payload."""
    from storage import queries

    for ip in ("45.33.32.1", "45.33.32.2"):
        for _ in range(3):
            db.add(
                make_event(
                    src_ip=ip,
                    event_type=EventType.AUTH_ATTEMPT.value,
                    username="root",
                    password="hunter2",
                )
            )
    for ip in ("93.184.216.1", "93.184.216.2"):
        db.add(
            make_event(
                src_ip=ip,
                event_type=EventType.FILE_UPLOAD.value,
                payload_sha256="a" * 64,
                username="oracle",
                password="oracle",
            )
        )
    db.commit()
    queries.rebuild_attackers(db)
    db.commit()


class TestDatabasePath:
    def test_fingerprints_are_built_from_attackers(self, db, two_campaigns):
        prints = campaigns.build_fingerprints(db)
        assert len(prints) == 4
        assert {p.src_ip for p in prints} >= {"45.33.32.1", "93.184.216.1"}

    def test_payload_hashes_are_attached(self, db, two_campaigns):
        prints = {p.src_ip: p for p in campaigns.build_fingerprints(db)}
        assert "a" * 64 in prints["93.184.216.1"].payloads
        assert prints["45.33.32.1"].payloads == frozenset()

    def test_credential_sharers_cluster(self, db, two_campaigns):
        found = campaigns.find_campaigns(db)
        members = {tuple(c.members) for c in found}
        assert ("45.33.32.1", "45.33.32.2") in members

    def test_payload_sharers_cluster(self, db, two_campaigns):
        found = campaigns.find_campaigns(db)
        members = {tuple(c.members) for c in found}
        assert ("93.184.216.1", "93.184.216.2") in members

    def test_the_two_campaigns_stay_distinct(self, db, two_campaigns):
        found = campaigns.find_campaigns(db)
        assert len(found) == 2

    def test_empty_database_yields_no_campaigns(self, db):
        assert campaigns.find_campaigns(db) == []


class TestCli:
    def test_reports_campaigns(self, db, two_campaigns, monkeypatch, capsys, db_url):
        monkeypatch.setenv("DATABASE_URL", db_url)
        assert campaigns.main([]) == 0
        assert "campaign 1:" in capsys.readouterr().out

    def test_json_output(self, db, two_campaigns, monkeypatch, capsys, db_url):
        import json

        monkeypatch.setenv("DATABASE_URL", db_url)
        campaigns.main(["--json"])
        assert len(json.loads(capsys.readouterr().out)) == 2

    def test_identical_behaviour_clusters_even_at_a_brutal_threshold(
        self, db, two_campaigns, monkeypatch, capsys, db_url
    ):
        # These sources behave *identically*, so they score exactly 1.0. A
        # threshold of 0.999 is not an impossible bar for them.
        monkeypatch.setenv("DATABASE_URL", db_url)
        assert campaigns.main(["--threshold", "0.999"]) == 0
        assert "2 campaign(s)" in capsys.readouterr().out

    def test_unreachable_threshold_finds_nothing(
        self, db, two_campaigns, monkeypatch, capsys, db_url
    ):
        # Similarity is bounded at 1.0, so nothing can clear this.
        monkeypatch.setenv("DATABASE_URL", db_url)
        assert campaigns.main(["--threshold", "1.01"]) == 0
        assert "no campaigns found" in capsys.readouterr().err


class TestCredentialPairsAreReal:
    """A cited credential must be one that was actually tried.

    The aggregate stores top usernames and top passwords as two separate
    lists. Combining them would manufacture pairs nobody ever sent — and a
    campaign whose evidence is invented is worse than no campaign, because it
    looks checkable and is not.
    """

    def test_pairs_come_from_events_not_a_cross_product(self, db, make_event):
        from storage import queries

        # This source tried root:aaa and admin:bbb. It never tried root:bbb.
        for username, password in [("root", "aaa"), ("admin", "bbb")]:
            db.add(
                make_event(
                    src_ip="45.33.32.7",
                    event_type=EventType.AUTH_ATTEMPT.value,
                    username=username,
                    password=password,
                )
            )
        db.commit()
        queries.rebuild_attackers(db)
        db.commit()

        prints = {p.src_ip: p for p in campaigns.build_fingerprints(db)}
        creds = prints["45.33.32.7"].credentials
        assert creds == {"root:aaa", "admin:bbb"}
        assert "root:bbb" not in creds
        assert "admin:aaa" not in creds

    def test_events_missing_half_a_pair_are_skipped(self, db, make_event):
        from storage import queries

        db.add(
            make_event(
                src_ip="45.33.32.8",
                event_type=EventType.AUTH_ATTEMPT.value,
                username="root",
                password=None,
            )
        )
        db.commit()
        queries.rebuild_attackers(db)
        db.commit()

        prints = {p.src_ip: p for p in campaigns.build_fingerprints(db)}
        assert prints["45.33.32.8"].credentials == frozenset()
        assert "root" in prints["45.33.32.8"].usernames
