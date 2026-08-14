"""IP geolocation.

Two backends, tried in order:

1. **MaxMind GeoLite2** (``pip install geoip2`` plus a ``.mmdb`` in
   ``data/geolite2/``). Real data, real accuracy.
2. **Nothing.** If the database is absent the lookup returns ``None`` country
   with ``geo_source="unavailable"``.

There is deliberately no third "estimate it from the IP range" backend. A
plausible-looking country guessed from an arbitrary range is indistinguishable
downstream from a real lookup, and an analyst who attributes an intrusion to the
wrong country because the dashboard invented one is worse off than an analyst
who sees a blank. Missing data must look missing.

Synthetic demo data is the one exception: :func:`synthetic_geo` produces stable
fake coordinates and always stamps ``geo_source="synthetic"`` so it can never be
confused with a measurement. ``tools/seed_fake_data.py`` is its only caller.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger("pipeline.geoip")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
GEOLITE_DIR = PROJECT_ROOT / "data" / "geolite2"
# Recognised city databases, checked in order. DB-IP Lite is the no-account,
# no-license-key alternative to MaxMind GeoLite2 — same MMDB format, so the
# geoip2 reader opens it unchanged.
CITY_DB_NAMES = ("GeoLite2-City.mmdb", "GeoIP2-City.mmdb")
CITY_DB_GLOBS = ("dbip-city-lite-*.mmdb", "dbip-city-*.mmdb", "*city*.mmdb")

_reader = None
_reader_lock = threading.Lock()
_reader_attempted = False


def _get_reader():
    """Open the MaxMind reader once per process, or give up quietly."""
    global _reader, _reader_attempted
    if _reader is not None or _reader_attempted:
        return _reader

    with _reader_lock:
        if _reader_attempted:
            return _reader
        _reader_attempted = True

        try:
            import geoip2.database
        except ImportError:
            log.info("geoip2 not installed; geolocation disabled")
            return None

        for path in _candidate_city_dbs():
            try:
                _reader = geoip2.database.Reader(str(path))
                log.info("geolocation enabled using %s", path.name)
                return _reader
            except Exception as exc:  # pragma: no cover - corrupt db
                log.warning("could not open %s: %s", path, exc)

        log.info(
            "no city database found in %s; geolocation disabled "
            "(drop a MaxMind GeoLite2-City.mmdb or a free DB-IP dbip-city-lite-*.mmdb here)",
            GEOLITE_DIR,
        )
        return None


def _candidate_city_dbs() -> list[Path]:
    """City databases present in the geolite2 dir, fixed names before globs."""
    candidates: list[Path] = []
    for name in CITY_DB_NAMES:
        path = GEOLITE_DIR / name
        if path.exists():
            candidates.append(path)
    if GEOLITE_DIR.is_dir():
        for pattern in CITY_DB_GLOBS:
            for path in sorted(GEOLITE_DIR.glob(pattern), reverse=True):
                if path not in candidates and "asn" not in path.name.lower():
                    candidates.append(path)
    return candidates


# --------------------------------------------------------------------------- #
# Address classification — always available, no database needed
# --------------------------------------------------------------------------- #


def classify_address(ip: str) -> dict[str, Any]:
    """Structural facts about an address that need no external data."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"valid": False, "version": None, "scope": "invalid"}

    if addr.is_loopback:
        scope = "loopback"
    elif addr.is_private:
        scope = "private"
    elif addr.is_link_local:
        scope = "link-local"
    elif addr.is_multicast:
        scope = "multicast"
    elif addr.is_reserved or addr.is_unspecified:
        scope = "reserved"
    else:
        scope = "public"

    return {
        "valid": True,
        "version": addr.version,
        "scope": scope,
        # A "bogon" source address on inbound internet traffic is spoofed or
        # locally generated — either way it should not be attributed to a country.
        "is_bogon": scope not in ("public",),
    }


def lookup(ip: str) -> dict[str, Any]:
    """Geolocate ``ip``. Always returns the same key set."""
    empty = {
        "country": None,
        "country_name": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "geo_source": "unavailable",
    }

    classification = classify_address(ip)
    if not classification["valid"]:
        return {**empty, "geo_source": "invalid-address"}
    if classification["is_bogon"]:
        return {**empty, "geo_source": classification["scope"]}

    reader = _get_reader()
    if reader is None:
        return empty

    try:
        response = reader.city(ip)
    except Exception:
        # geoip2 raises AddressNotFoundError for unallocated space, which is a
        # normal outcome rather than a failure.
        return {**empty, "geo_source": "not-found"}

    return {
        "country": response.country.iso_code,
        "country_name": response.country.name,
        "city": response.city.name,
        "latitude": float(response.location.latitude) if response.location.latitude else None,
        "longitude": float(response.location.longitude) if response.location.longitude else None,
        "geo_source": "geolite2",
    }


# --------------------------------------------------------------------------- #
# Synthetic geo, for demo data only
# --------------------------------------------------------------------------- #

# (ISO code, name, lat, lon) for cities used by the seeder. Coordinates are the
# real city centres; the *assignment* of an IP to one of them is fabricated.
SYNTHETIC_LOCATIONS: list[tuple[str, str, str, float, float]] = [
    ("CN", "China", "Shanghai", 31.2304, 121.4737),
    ("US", "United States", "Ashburn", 39.0438, -77.4874),
    ("RU", "Russia", "Moscow", 55.7558, 37.6173),
    ("BR", "Brazil", "Sao Paulo", -23.5505, -46.6333),
    ("IN", "India", "Mumbai", 19.0760, 72.8777),
    ("DE", "Germany", "Frankfurt", 50.1109, 8.6821),
    ("NL", "Netherlands", "Amsterdam", 52.3676, 4.9041),
    ("VN", "Vietnam", "Hanoi", 21.0278, 105.8342),
    ("KR", "South Korea", "Seoul", 37.5665, 126.9780),
    ("GB", "United Kingdom", "London", 51.5074, -0.1278),
    ("FR", "France", "Paris", 48.8566, 2.3522),
    ("SG", "Singapore", "Singapore", 1.3521, 103.8198),
    ("ID", "Indonesia", "Jakarta", -6.2088, 106.8456),
    ("TR", "Turkey", "Istanbul", 41.0082, 28.9784),
    ("UA", "Ukraine", "Kyiv", 50.4501, 30.5234),
    ("IR", "Iran", "Tehran", 35.6892, 51.3890),
    ("RO", "Romania", "Bucharest", 44.4268, 26.1025),
    ("MX", "Mexico", "Mexico City", 19.4326, -99.1332),
    ("ZA", "South Africa", "Johannesburg", -26.2041, 28.0473),
    ("JP", "Japan", "Tokyo", 35.6762, 139.6503),
]


def synthetic_geo(ip: str) -> dict[str, Any]:
    """Deterministic fake geolocation for seeded demo data.

    Same IP always maps to the same city, so a demo dataset looks coherent
    across reloads. ``geo_source`` is always ``"synthetic"``.
    """
    digest = hashlib.sha256(ip.encode()).digest()
    country, country_name, city, lat, lon = SYNTHETIC_LOCATIONS[
        digest[0] % len(SYNTHETIC_LOCATIONS)
    ]
    # Scatter within roughly a degree so points do not stack perfectly.
    jitter_lat = ((digest[1] / 255) - 0.5) * 1.6
    jitter_lon = ((digest[2] / 255) - 0.5) * 1.6
    return {
        "country": country,
        "country_name": country_name,
        "city": city,
        "latitude": round(lat + jitter_lat, 4),
        "longitude": round(lon + jitter_lon, 4),
        "geo_source": "synthetic",
    }


def close() -> None:
    """Release the MaxMind reader. Used by tests."""
    global _reader, _reader_attempted
    if _reader is not None:
        try:
            _reader.close()
        except Exception:
            pass
    _reader = None
    _reader_attempted = False


__all__ = ["lookup", "classify_address", "synthetic_geo", "SYNTHETIC_LOCATIONS", "close"]
