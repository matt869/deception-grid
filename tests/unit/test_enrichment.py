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

    def test_private_ip_has_no_indicator_match(self):
        # No indicator files loaded in CI; a clean IP scores zero.
        assert threat_intel.check_ip("192.0.2.99")["ti_score"] == 0.0

    def test_enrich_combines_signals(self):
        result = threat_intel.enrich(
            "192.0.2.1", user_agent="masscan/1.3", username="admin"
        )
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
