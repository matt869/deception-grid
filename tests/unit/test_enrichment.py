"""Unit tests for the enrichment pipeline.

These lean hard on the "missing data must look missing" and "never call out"
invariants from the enrichment modules — the properties that keep the dashboard
honest and the sensor quiet.
"""

from __future__ import annotations

import pytest

from pipeline.enrichment import asn, geoip, threat_intel

# --------------------------------------------------------------------------- #
# GeoIP
# --------------------------------------------------------------------------- #


class TestGeoIP:
    def test_private_address_is_not_geolocated(self):
        result = geoip.lookup("192.168.1.1")
        assert result["country"] is None
        assert result["geo_source"] == "private"

    def test_loopback_is_flagged(self):
        assert geoip.classify_address("127.0.0.1")["scope"] == "loopback"

    def test_invalid_address(self):
        result = geoip.lookup("not-an-ip")
        assert result["country"] is None
        assert result["geo_source"] == "invalid-address"

    def test_public_address_without_db_is_unavailable_not_guessed(self):
        # Without a GeoLite2 file, a public IP must return no country, never a
        # fabricated one. (CI has no .mmdb.)
        result = geoip.lookup("8.8.8.8")
        assert result["geo_source"] in ("unavailable", "geolite2", "not-found")
        if result["geo_source"] == "unavailable":
            assert result["country"] is None

    def test_synthetic_is_deterministic_and_labelled(self):
        a = geoip.synthetic_geo("203.0.113.5")
        b = geoip.synthetic_geo("203.0.113.5")
        assert a == b
        assert a["geo_source"] == "synthetic"
        assert a["country"] is not None  # synthetic always assigns one

    def test_synthetic_differs_by_ip(self):
        # Not a guarantee for every pair, but these two map to different cities.
        a = geoip.synthetic_geo("203.0.113.5")
        b = geoip.synthetic_geo("198.51.100.200")
        assert (a["latitude"], a["longitude"]) != (b["latitude"], b["longitude"])

    def test_classify_bogon(self):
        assert geoip.classify_address("10.0.0.1")["is_bogon"] is True
        assert geoip.classify_address("8.8.8.8")["is_bogon"] is False


# --------------------------------------------------------------------------- #
# ASN
# --------------------------------------------------------------------------- #


class TestASN:
    def test_private_address_has_no_asn(self):
        assert asn.lookup("10.0.0.1")["asn"] is None

    def test_hosting_provider_classification(self):
        assert "hosting-provider" in asn.classify_org("Amazon.com, Inc.")
        assert "hosting-provider" in asn.classify_org("DigitalOcean, LLC")

    def test_consumer_isp_classification(self):
        assert "consumer-isp" in asn.classify_org("Comcast Cable Communications")

    def test_vpn_tor_classification(self):
        assert "vpn-or-tor" in asn.classify_org("Tor Exit Relay")

    def test_empty_org_classifies_to_nothing(self):
        assert asn.classify_org(None) == []
        assert asn.classify_org("") == []

    def test_synthetic_asn_is_private_range(self):
        # Must never collide with a real, routable ASN.
        result = asn.synthetic_asn("203.0.113.5")
        assert 64512 <= result["asn"] <= 65534
        assert result["asn_source"] == "synthetic"


# --------------------------------------------------------------------------- #
# Threat intel
# --------------------------------------------------------------------------- #


class TestThreatIntel:
    def test_mozi_substring_does_not_match_mozilla(self):
        # Regression guard for the "mozi" in "mozilla" false positive.
        result = threat_intel.check_user_agent(
            "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36"
        )
        assert "malware:mozi" not in result["ti_tags"]
        assert result["ti_score"] == 0.0

    def test_real_mozi_agent_matches(self):
        assert "malware:mozi" in threat_intel.check_user_agent("Mozi.m")["ti_tags"]

    def test_scanner_user_agent_flagged(self):
        result = threat_intel.check_user_agent("sqlmap/1.7.2#stable")
        assert "scanner:sqlmap" in result["ti_tags"]
        assert result["ti_score"] > 0

    def test_curl_matches_with_trailing_slash(self):
        assert "tool:curl" in threat_intel.check_user_agent("curl/7.81.0")["ti_tags"]

    def test_empty_user_agent(self):
        assert threat_intel.check_user_agent(None)["ti_score"] == 0.0

    def test_generic_username_flagged(self):
        assert "cred:generic-username" in threat_intel.check_username("root")["ti_tags"]

    def test_specific_username_not_flagged_generic(self):
        result = threat_intel.check_username("j.smith.finance")
        assert "cred:specific-username" in result["ti_tags"]

    def test_ip_with_no_indicator_loaded_scores_zero(self, tmp_path, monkeypatch):
        """A source matching nothing scores zero.

        The indicator directory is redirected at an empty temp dir rather than
        assumed empty. It is not: a real deployment mounts live feeds, and
        FireHOL's level-1 list contains the RFC 5737 documentation ranges — so
        the previous version of this test passed in CI and failed on the sensor,
        which is the worst way for a test to be wrong.
        """
        monkeypatch.setattr(threat_intel, "INDICATOR_DIR", tmp_path)
        threat_intel.reload_indicators()
        try:
            assert threat_intel.check_ip("192.0.2.99")["ti_score"] == 0.0
        finally:
            # Restore the process-wide cache for whatever runs next.
            threat_intel.reload_indicators()

    def test_enrich_combines_signals(self):
        result = threat_intel.enrich("192.0.2.1", user_agent="masscan/1.3", username="admin")
        assert result["threat_score"] > 0
        assert "scanner:masscan" in result["threat_tags"]


class TestEnrichEvent:
    def test_enriches_in_place(self):
        from pipeline.enrichment import enrich_event

        event = {"src_ip": "203.0.113.7", "user_agent": "zgrab/0.x"}
        returned = enrich_event(event, synthetic=True)
        assert returned is event  # mutated in place
        assert event["geo_source"] == "synthetic"
        assert event["asn"] is not None
        assert "scanner:zgrab" in event["threat_tags"]

    def test_missing_src_ip_is_safe(self):
        from pipeline.enrichment import enrich_event

        event = {"event_type": "connect"}
        enrich_event(event)  # must not raise

    def test_enrichment_never_raises_on_garbage(self):
        from pipeline.enrichment import enrich_event

        event = {"src_ip": "!!!garbage!!!", "user_agent": None}
        enrich_event(event)  # must not raise


# --------------------------------------------------------------------------- #
# ASN prefix table
# --------------------------------------------------------------------------- #
#
# These use real routable ranges (45.33.32.0/24, 2606:4700::/32) rather than the
# documentation ranges the rest of the suite uses for source addresses. That is
# not a style choice: ``ipaddress`` classifies the RFC 5737 and RFC 3849
# documentation blocks as *private*, so ``asn.lookup("203.0.113.9")`` returns
# ``asn_source="private"`` and short-circuits before the prefix table is ever
# consulted. A test written with 203.0.113.x would pass while covering nothing.


@pytest.fixture
def prefix_table(tmp_path, monkeypatch):
    """Point the ASN module at a temp prefix table and reset its caches.

    The mmdb reader is stubbed out as well, not assumed absent. A deployment
    that has GeoLite2-ASN installed would otherwise never reach the prefix
    table and these tests would pass without exercising a single line of it —
    the same trap ``test_ip_with_no_indicator_loaded_scores_zero`` documents.
    """
    monkeypatch.setattr(asn, "_get_reader", lambda: None)

    def _write(content: str):
        path = tmp_path / "asn_prefixes.tsv"
        path.write_text(content, encoding="utf-8")
        monkeypatch.setattr(asn, "PREFIX_TABLE", path)
        asn.close()  # drop any table cached by an earlier test
        return path

    yield _write
    asn.close()  # and don't leak this one into the next


class TestASNPrefixTable:
    def test_lookup_resolves_from_the_table(self, prefix_table):
        prefix_table("45.33.32.0/24\t64500\tExample Networks\n")
        result = asn.lookup("45.33.32.9")
        assert result["asn"] == 64500
        assert result["as_org"] == "Example Networks"
        assert result["asn_source"] == "prefix-table"

    def test_longest_prefix_wins(self, prefix_table):
        # Routing picks the most specific route; so must we. Listed least
        # specific first so a naive first-match would return the wrong one.
        prefix_table(
            "45.0.0.0/8\t64500\tBroad Allocation\n45.33.32.0/24\t64501\tSpecific Carve-Out\n"
        )
        assert asn.lookup("45.33.32.9")["asn"] == 64501

    def test_address_outside_every_prefix_is_unavailable(self, prefix_table):
        prefix_table("45.33.32.0/24\t64500\tExample Networks\n")
        result = asn.lookup("8.8.8.8")
        assert result["asn"] is None
        assert result["asn_source"] == "unavailable"

    def test_missing_table_file_is_not_an_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(asn, "_get_reader", lambda: None)
        monkeypatch.setattr(asn, "PREFIX_TABLE", tmp_path / "does-not-exist.tsv")
        asn.close()
        try:
            assert asn.lookup("45.33.32.9")["asn_source"] == "unavailable"
        finally:
            asn.close()

    def test_as_prefixed_numbers_are_accepted(self, prefix_table):
        prefix_table("45.33.32.0/24\tAS64500\tExample Networks\n")
        assert asn.lookup("45.33.32.9")["asn"] == 64500

    def test_org_column_is_optional(self, prefix_table):
        prefix_table("45.33.32.0/24\t64500\n")
        result = asn.lookup("45.33.32.9")
        assert result["asn"] == 64500
        assert result["as_org"] is None  # empty must read as missing, not ""

    def test_comments_and_blank_lines_are_skipped(self, prefix_table):
        prefix_table("# RIR export, trimmed\n\n45.33.32.0/24\t64500\tExample Networks\n\n# end\n")
        assert asn.lookup("45.33.32.9")["asn"] == 64500

    def test_malformed_lines_do_not_discard_the_good_ones(self, prefix_table):
        # One bad line in a downloaded RIR export must not blank the table.
        prefix_table(
            "not-a-prefix\tnonsense\n"
            "45.33.32.0/24\tnot-a-number\n"
            "only-one-column\n"
            "45.33.32.0/24\t64500\tExample Networks\n"
        )
        assert asn.lookup("45.33.32.9")["asn"] == 64500

    def test_comma_separated_fallback_is_parsed(self, prefix_table):
        prefix_table("45.33.32.0/24,64500,Example Networks\n")
        assert asn.lookup("45.33.32.9")["asn"] == 64500

    def test_host_address_is_accepted_as_a_prefix(self, prefix_table):
        # strict=False, so a bare address means a /32.
        prefix_table("45.33.32.9\t64500\tExample Networks\n")
        assert asn.lookup("45.33.32.9")["asn"] == 64500
        assert asn.lookup("45.33.32.10")["asn"] is None

    def test_ipv6_prefixes_resolve(self, prefix_table):
        prefix_table("2606:4700::/32\t64500\tExample IPv6\n")
        assert asn.lookup("2606:4700::1")["asn"] == 64500

    def test_address_families_do_not_cross_match(self, prefix_table):
        prefix_table("2606:4700::/32\t64500\tExample IPv6\n")
        assert asn.lookup("45.33.32.9")["asn"] is None

    def test_table_is_cached_after_the_first_read(self, prefix_table):
        path = prefix_table("45.33.32.0/24\t64500\tExample Networks\n")
        assert asn.lookup("45.33.32.9")["asn"] == 64500
        path.unlink()  # cache must survive the file going away
        assert asn.lookup("45.33.32.9")["asn"] == 64500

    def test_close_forces_a_reload(self, prefix_table):
        prefix_table("45.33.32.0/24\t64500\tOld Org\n")
        assert asn.lookup("45.33.32.9")["as_org"] == "Old Org"
        prefix_table("45.33.32.0/24\t64500\tNew Org\n")
        assert asn.lookup("45.33.32.9")["as_org"] == "New Org"

    def test_private_addresses_never_reach_the_table(self, prefix_table):
        # 10.0.0.0/8 in the table must still not produce an ASN for a private
        # source — those are our own network, not somebody's allocation.
        prefix_table("10.0.0.0/8\t64500\tShould Never Match\n")
        result = asn.lookup("10.1.2.3")
        assert result["asn"] is None
        assert result["asn_source"] == "private"

    def test_link_local_is_treated_as_private(self, prefix_table):
        prefix_table("169.254.0.0/16\t64500\tShould Never Match\n")
        assert asn.lookup("169.254.1.1")["asn_source"] == "private"

    def test_enrich_adds_operator_tags_from_the_table(self, prefix_table):
        prefix_table("45.33.32.0/24\t64500\tDigitalOcean, LLC\n")
        result = asn.enrich("45.33.32.9")
        assert result["asn"] == 64500
        assert "hosting-provider" in result["asn_tags"]

    def test_enrich_on_an_unknown_address_yields_no_tags(self, prefix_table):
        prefix_table("45.33.32.0/24\t64500\tExample Networks\n")
        assert asn.enrich("8.8.8.8")["asn_tags"] == []
