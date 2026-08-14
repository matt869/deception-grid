"""ASN and network-ownership lookup.

Backends, tried in order:

1. **MaxMind GeoLite2-ASN** (``data/geolite2/GeoLite2-ASN.mmdb``) if ``geoip2``
   is installed.
2. **A local prefix table** at ``data/asn_prefixes.tsv``, format
   ``prefix<TAB>asn<TAB>organisation`` — one line per CIDR. Lets you drop in an
   export from any RIR or a hand-curated list of cloud ranges without adding a
   dependency. Lookups use a longest-prefix match, so a /24 carved out of a /16
   wins, which is how routing actually works.
3. **Nothing** — returns ``None``, same reasoning as ``geoip.py``: absent data
   must look absent.

Hosting-provider classification is separate and *does* work offline, because it
only needs the organisation string. Knowing that traffic comes from a bulletproof
host or a VPS provider rather than a residential line changes how you triage it.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger("pipeline.asn")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
GEOLITE_DIR = PROJECT_ROOT / "data" / "geolite2"
ASN_DB_NAME = "GeoLite2-ASN.mmdb"
# DB-IP Lite ASN is the free, no-key alternative to GeoLite2-ASN (same format).
ASN_DB_GLOBS = ("dbip-asn-lite-*.mmdb", "dbip-asn-*.mmdb")
PREFIX_TABLE = PROJECT_ROOT / "data" / "asn_prefixes.tsv"

_reader = None
_reader_attempted = False
_prefix_table: list[tuple[Any, int, str]] | None = None
_lock = threading.Lock()


# Organisation-name patterns that indicate infrastructure rather than an
# end-user connection. Substring match, case-insensitive.
HOSTING_PATTERNS = (
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "digitalocean",
    "linode",
    "vultr",
    "ovh",
    "hetzner",
    "scaleway",
    "contabo",
    "leaseweb",
    "choopa",
    "m247",
    "cloudflare",
    "alibaba",
    "tencent",
    "oracle cloud",
    "hostinger",
    "godaddy",
    "namecheap",
    "colocrossing",
    "quadranet",
    "psychz",
    "datacamp",
)
VPN_TOR_PATTERNS = (
    "nordvpn",
    "expressvpn",
    "privateinternetaccess",
    "mullvad",
    "surfshark",
    "protonvpn",
    "cyberghost",
    "tor exit",
    "torservers",
    "relay",
)


def _get_reader():
    global _reader, _reader_attempted
    if _reader is not None or _reader_attempted:
        return _reader
    with _lock:
        if _reader_attempted:
            return _reader
        _reader_attempted = True
        try:
            import geoip2.database
        except ImportError:
            return None
        path = None
        fixed = GEOLITE_DIR / ASN_DB_NAME
        if fixed.exists():
            path = fixed
        elif GEOLITE_DIR.is_dir():
            for pattern in ASN_DB_GLOBS:
                matches = sorted(GEOLITE_DIR.glob(pattern), reverse=True)
                if matches:
                    path = matches[0]
                    break
        if path is None:
            log.info(
                "no ASN database found in %s; ASN lookup falls back to the prefix table",
                GEOLITE_DIR,
            )
            return None
        try:
            _reader = geoip2.database.Reader(str(path))
            log.info("ASN lookup enabled using %s", path.name)
        except Exception as exc:  # pragma: no cover
            log.warning("could not open %s: %s", path, exc)
        return _reader


def _get_prefix_table() -> list[tuple[Any, int, str]]:
    """Load and cache ``data/asn_prefixes.tsv``, sorted longest-prefix first."""
    global _prefix_table
    if _prefix_table is not None:
        return _prefix_table

    with _lock:
        if _prefix_table is not None:
            return _prefix_table

        table: list[tuple[Any, int, str]] = []
        if PREFIX_TABLE.exists():
            for lineno, raw in enumerate(PREFIX_TABLE.read_text(encoding="utf-8").splitlines(), 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) < 2:
                    parts = re.split(r"\s{2,}|,", line)
                if len(parts) < 2:
                    log.debug("%s:%d skipped (need prefix<TAB>asn[<TAB>org])", PREFIX_TABLE, lineno)
                    continue
                try:
                    network = ipaddress.ip_network(parts[0].strip(), strict=False)
                    asn = int(parts[1].strip().upper().removeprefix("AS"))
                except ValueError:
                    log.debug("%s:%d skipped (unparseable)", PREFIX_TABLE, lineno)
                    continue
                org = parts[2].strip() if len(parts) > 2 else ""
                table.append((network, asn, org))

            # Longest prefix first so the first match is the most specific.
            table.sort(key=lambda row: row[0].prefixlen, reverse=True)
            log.info("loaded %d ASN prefixes from %s", len(table), PREFIX_TABLE.name)

        _prefix_table = table
        return table


def lookup(ip: str) -> dict[str, Any]:
    """Return ASN details for ``ip``. Always the same key set."""
    empty: dict[str, Any] = {"asn": None, "as_org": None, "asn_source": "unavailable"}

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {**empty, "asn_source": "invalid-address"}
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return {**empty, "asn_source": "private"}

    reader = _get_reader()
    if reader is not None:
        try:
            response = reader.asn(ip)
            return {
                "asn": response.autonomous_system_number,
                "as_org": response.autonomous_system_organization,
                "asn_source": "geolite2-asn",
            }
        except Exception:
            pass  # fall through to the prefix table

    for network, asn, org in _get_prefix_table():
        if addr.version == network.version and addr in network:
            return {"asn": asn, "as_org": org or None, "asn_source": "prefix-table"}

    return empty


def classify_org(as_org: str | None) -> list[str]:
    """Tag a network operator. Works with no database at all."""
    if not as_org:
        return []
    lowered = as_org.lower()
    tags: list[str] = []
    if any(p in lowered for p in HOSTING_PATTERNS):
        tags.append("hosting-provider")
    if any(p in lowered for p in VPN_TOR_PATTERNS):
        tags.append("vpn-or-tor")
    if any(p in lowered for p in ("telecom", "broadband", "cable", "dsl", "mobile", "wireless")):
        tags.append("consumer-isp")
    if "university" in lowered or "education" in lowered or "academ" in lowered:
        tags.append("academic")
    return tags


def enrich(ip: str) -> dict[str, Any]:
    """ASN lookup plus operator classification."""
    result = lookup(ip)
    result["asn_tags"] = classify_org(result.get("as_org"))
    return result


def synthetic_asn(ip: str) -> dict[str, Any]:
    """Deterministic fake ASN for seeded demo data. Never a real allocation.

    Uses the 64512–65534 private-use ASN range so a demo row can never be
    mistaken for, or attributed to, a real network operator.
    """
    import hashlib

    digest = hashlib.sha256(("asn:" + ip).encode()).digest()
    orgs = [
        "Example Hosting BV",
        "Demo Cloud Services",
        "Sample Telecom",
        "Placeholder Datacenter",
        "Test Network Operator",
        "Synthetic Broadband",
    ]
    return {
        "asn": 64512 + (int.from_bytes(digest[:2], "big") % 1022),
        "as_org": orgs[digest[3] % len(orgs)],
        "asn_source": "synthetic",
    }


def close() -> None:
    """Release cached state. Used by tests."""
    global _reader, _reader_attempted, _prefix_table
    if _reader is not None:
        try:
            _reader.close()
        except Exception:
            pass
    _reader = None
    _reader_attempted = False
    _prefix_table = None


__all__ = [
    "lookup",
    "enrich",
    "classify_org",
    "synthetic_asn",
    "close",
    "HOSTING_PATTERNS",
    "VPN_TOR_PATTERNS",
]
