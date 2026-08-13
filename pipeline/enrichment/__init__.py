"""Event enrichment: geolocation, network ownership and threat intelligence.

:func:`enrich_event` is the single entry point used by the honeypot's writer
thread and by the batch backfill tool. It mutates the event dict in place and
never raises — enrichment failing must not cost us the observation itself,
which is the part we cannot recreate.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from pipeline.enrichment import asn, geoip, threat_intel

log = logging.getLogger("pipeline.enrichment")


def enrich_event(event: dict[str, Any], synthetic: bool = False) -> dict[str, Any]:
    """Add geo, ASN and threat-intel fields to an event dict, in place.

    Set ``synthetic=True`` only for generated demo data; it fills geo and ASN
    from the deterministic fake generators, which stamp their source fields so
    the result is never mistaken for a measurement.
    """
    src_ip = event.get("src_ip")
    if not src_ip:
        return event

    try:
        if synthetic:
            event.update(geoip.synthetic_geo(src_ip))
            asn_result = asn.synthetic_asn(src_ip)
        else:
            event.update(geoip.lookup(src_ip))
            asn_result = asn.enrich(src_ip)

        event["asn"] = asn_result.get("asn")
        event["as_org"] = asn_result.get("as_org")

        intel = threat_intel.enrich(
            src_ip,
            user_agent=event.get("user_agent"),
            username=event.get("username"),
        )
        event["threat_score"] = intel["threat_score"]

        tags = list(intel["threat_tags"]) + list(asn_result.get("asn_tags") or [])
        event["threat_tags"] = tags
    except Exception as exc:  # noqa: BLE001 - see module docstring
        log.debug("enrichment failed for %s: %s", src_ip, exc)

    return event


def enrich_ip(src_ip: str, synthetic: bool = False) -> dict[str, Any]:
    """Enrichment for a bare IP, used by the API's on-demand lookup endpoint."""
    result: dict[str, Any] = {"src_ip": src_ip}
    result.update(geoip.synthetic_geo(src_ip) if synthetic else geoip.lookup(src_ip))
    result.update(asn.synthetic_asn(src_ip) if synthetic else asn.enrich(src_ip))
    result.update(threat_intel.enrich(src_ip))
    result.update(geoip.classify_address(src_ip))
    return result


__all__ = ["enrich_event", "enrich_ip", "geoip", "asn", "threat_intel"]
