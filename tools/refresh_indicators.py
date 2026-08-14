"""Refresh local threat-intel indicator files from public blocklist feeds.

    python -m tools.refresh_indicators --feed blocklist-de https://lists.blocklist.de/lists/all.txt
    python -m tools.refresh_indicators --defaults          # a small curated set
    INDICATOR_FEEDS="name=url,name2=url2" python -m tools.refresh_indicators

This is the **one** place the project fetches over the network, and it is an
explicit, operator-run action — never part of enrichment (see
``pipeline.enrichment.threat_intel`` for why enrichment must stay offline). Each
feed is written to ``data/indicators/<name>.txt``, which the enrichment layer
picks up so ``known-bad-source`` / high-score matches fire against real feeds.

Only IPv4/IPv6 addresses and CIDRs are kept; everything else in a feed (comments,
domains, hashes) is ignored. Feeds are your choice — a few reputable free ones
are listed under ``--defaults``, but review a feed's licence and false-positive
profile before you act on it.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INDICATOR_DIR = PROJECT_ROOT / "data" / "indicators"

# Reputable, free, widely-used feeds. Not fetched unless you pass --defaults;
# review each before relying on it.
DEFAULT_FEEDS = {
    "blocklist-de": "https://lists.blocklist.de/lists/all.txt",
    "ipsum": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "firehol-level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
}

MAX_FEED_BYTES = 25 * 1024 * 1024  # a feed larger than this is almost certainly wrong


def _keep_indicators(text: str) -> list[str]:
    """Extract just the valid IP/CIDR tokens from a feed body."""
    kept: list[str] = []
    for raw in text.splitlines():
        token = raw.split("#")[0].split(";")[0].strip()
        if not token:
            continue
        # Some feeds prefix a score/column; take the first whitespace field.
        token = token.split()[0].strip()
        try:
            if "/" in token:
                ipaddress.ip_network(token, strict=False)
            else:
                ipaddress.ip_address(token)
        except ValueError:
            continue
        kept.append(token)
    return kept


def _fetch(url: str, timeout: float = 30.0) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "honeypot-indicator-refresh/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as resp:
        data = resp.read(MAX_FEED_BYTES + 1)
    if len(data) > MAX_FEED_BYTES:
        raise ValueError(f"feed exceeds {MAX_FEED_BYTES} bytes; refusing")
    return data.decode("utf-8", "replace")


def refresh_feed(name: str, url: str) -> int:
    """Download one feed and write the valid indicators to its file."""
    INDICATOR_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(c for c in name if c.isalnum() or c in "-_") or "feed"
    body = _fetch(url)
    indicators = _keep_indicators(body)

    out = INDICATOR_DIR / f"{safe_name}.txt"
    header = f"# {name}\n# source: {url}\n# {len(indicators)} indicators\n"
    out.write_text(header + "\n".join(indicators) + "\n", encoding="utf-8")
    return len(indicators)


def _parse_env_feeds() -> dict[str, str]:
    raw = os.getenv("INDICATOR_FEEDS", "").strip()
    feeds: dict[str, str] = {}
    for item in raw.split(","):
        if "=" in item:
            name, _, url = item.partition("=")
            if name.strip() and url.strip():
                feeds[name.strip()] = url.strip()
    return feeds


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refresh threat-intel indicator feeds")
    parser.add_argument(
        "--feed",
        nargs=2,
        action="append",
        metavar=("NAME", "URL"),
        help="a feed to fetch (repeatable)",
        default=[],
    )
    parser.add_argument(
        "--defaults", action="store_true", help="use the built-in reputable feed set"
    )
    parser.add_argument(
        "--list-defaults", action="store_true", help="print the default feeds and exit"
    )
    parser.add_argument(
        "--reload-db",
        action="store_true",
        help="also refresh the in-process indicator cache (no-op for the running API)",
    )
    args = parser.parse_args(argv)

    if args.list_defaults:
        for name, url in DEFAULT_FEEDS.items():
            print(f"{name:<16} {url}")
        return 0

    feeds: dict[str, str] = {}
    if args.defaults:
        feeds.update(DEFAULT_FEEDS)
    feeds.update(_parse_env_feeds())
    feeds.update({name: url for name, url in args.feed})

    if not feeds:
        print(
            "no feeds given. Use --defaults, --feed NAME URL, or set INDICATOR_FEEDS.\n"
            "See --list-defaults for a starting set.",
            file=sys.stderr,
        )
        return 2

    total = 0
    for name, url in feeds.items():
        try:
            count = refresh_feed(name, url)
            total += count
            print(f"  {name:<16} {count:>8,} indicators  <- {url}")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            print(f"  {name:<16} FAILED: {exc}", file=sys.stderr)

    print(f"\nwrote {total:,} indicators across {len(feeds)} feed(s) to {INDICATOR_DIR}")

    # The running API/enricher reloads indicators lazily; force a reload here so
    # a CLI run in the same process picks them up immediately.
    try:
        from pipeline.enrichment.threat_intel import reload_indicators

        reload_indicators()
    except Exception:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
