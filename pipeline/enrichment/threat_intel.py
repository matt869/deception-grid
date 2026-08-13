"""Threat-intelligence matching against local indicator sets.

**This module never makes a network request during enrichment.** Every lookup
runs against indicators already on disk or in the ``indicators`` table. That is
a design constraint, not an optimisation: enrichment runs on data supplied by an
attacker, and a lookup that phones a third party on every observed IP leaks your
sensor's view to that third party and hands anyone who can watch your egress a
real-time feed of what you are seeing.

Refreshing indicator files is a separate, explicit operation —
:func:`refresh_from_file` imports a local file, and the CLI in
``tools/import_public_logs.py`` handles fetching. Enrichment only ever reads.

Indicator sources, all optional, all under ``data/``:

* ``data/indicators/*.txt``  — one IP or CIDR per line, ``#`` comments allowed.
  The filename becomes the source label, so ``data/indicators/ssh-bruteforce.txt``
  tags matches as ``ti:ssh-bruteforce``.
* the ``indicators`` table — for anything added through the API or a tool.

With no indicator files present, every lookup returns a zero score and the
pipeline carries on. Built-in heuristics that need no feed at all — known
scanner user-agents, credential-stuffing username patterns — always apply.
"""

from __future__ import annotations

import functools
import ipaddress
import logging
import re
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger("pipeline.threat_intel")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
INDICATOR_DIR = PROJECT_ROOT / "data" / "indicators"

# Score contributions. Kept small and additive so no single source can dominate;
# the final attacker score is clamped in pipeline.detection.scoring.
SCORE_EXACT_IP = 40.0
SCORE_CIDR = 25.0
SCORE_SCANNER_UA = 15.0
SCORE_MALWARE_UA = 30.0

_lock = threading.Lock()
_ip_index: dict[str, set[str]] | None = None
_cidr_index: list[tuple[Any, str]] | None = None


# --------------------------------------------------------------------------- #
# Built-in heuristics (no feed required)
# --------------------------------------------------------------------------- #

# User-agents that identify the tool rather than a browser. Presence is not
# inherently malicious — several are legitimate research scanners — so these
# score modestly and are tagged by name for the analyst to judge.
SCANNER_USER_AGENTS: dict[str, str] = {
    "zgrab": "scanner:zgrab",
    "masscan": "scanner:masscan",
    "nmap": "scanner:nmap",
    "nikto": "scanner:nikto",
    "sqlmap": "scanner:sqlmap",
    "dirbuster": "scanner:dirbuster",
    "gobuster": "scanner:gobuster",
    "wpscan": "scanner:wpscan",
    "nuclei": "scanner:nuclei",
    "curl/": "tool:curl",
    "wget/": "tool:wget",
    "python-requests": "tool:python-requests",
    "go-http-client": "tool:go-http",
    "libwww-perl": "tool:libwww",
    "censys": "research:censys",
    "shodan": "research:shodan",
    "internetmeasurement": "research:internet-measurement",
    "paloaltonetworks": "research:paloalto",
}

# Strings seen in the user-agent field of commodity malware and exploit kits.
MALWARE_USER_AGENTS: dict[str, str] = {
    "hello, world": "malware:mirai-variant",
    "xmrig": "malware:cryptominer",
    "mozi": "malware:mozi",
    "hakai": "malware:hakai",
    "botnet": "malware:generic-botnet",
}


@functools.lru_cache(maxsize=512)
def _needle_pattern(needle: str) -> re.Pattern[str]:
    """Compile a UA needle into a boundary-aware pattern.

    A plain substring test is wrong here, and wrong in the direction that
    matters: ``"mozi" in "mozilla/5.0 ..."`` is True, so every ordinary browser
    user-agent would be tagged as the Mozi botnet. A false "malware" verdict on
    routine traffic is far more damaging than a missed detection — it poisons
    the score, the classification and any blocklist exported from it.

    So each needle gets a word-boundary guard on whichever of its edges is
    alphanumeric. ``mozi`` will not match inside ``mozilla``, while ``curl/``
    still matches ``curl/7.81.0`` because its trailing ``/`` needs no guard.
    """
    escaped = re.escape(needle)
    prefix = r"(?<![a-z0-9])" if needle[:1].isalnum() else ""
    suffix = r"(?![a-z0-9])" if needle[-1:].isalnum() else ""
    return re.compile(prefix + escaped + suffix, re.IGNORECASE)


def _matches_needle(haystack: str, needle: str) -> bool:
    return _needle_pattern(needle).search(haystack) is not None


# Username patterns typical of automated credential stuffing rather than a
# targeted attempt against a known account.
GENERIC_USERNAMES = {
    "root",
    "admin",
    "administrator",
    "user",
    "test",
    "guest",
    "oracle",
    "ubuntu",
    "postgres",
    "mysql",
    "ftp",
    "www",
    "web",
    "support",
    "pi",
    "default",
    "operator",
    "service",
    "backup",
    "deploy",
    "git",
    "jenkins",
}


# --------------------------------------------------------------------------- #
# Indicator loading
# --------------------------------------------------------------------------- #


def _load_indices() -> tuple[dict[str, set[str]], list[tuple[Any, str]]]:
    """Build the in-memory indicator indices from disk and the database."""
    global _ip_index, _cidr_index
    if _ip_index is not None and _cidr_index is not None:
        return _ip_index, _cidr_index

    with _lock:
        if _ip_index is not None and _cidr_index is not None:
            return _ip_index, _cidr_index

        ip_index: dict[str, set[str]] = {}
        cidr_index: list[tuple[Any, str]] = []

        if INDICATOR_DIR.is_dir():
            for path in sorted(INDICATOR_DIR.glob("*.txt")):
                source = f"ti:{path.stem}"
                for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    _index_value(raw.split("#")[0].strip(), source, ip_index, cidr_index)

        # Anything added via the API or tools.
        try:
            from sqlalchemy import select

            from storage.db import session_scope
            from storage.models import Indicator

            with session_scope() as db:
                rows = db.execute(select(Indicator).where(Indicator.enabled.is_(True))).scalars()
                for row in rows:
                    if row.kind in ("ip", "cidr"):
                        _index_value(row.value, f"ti:{row.source}", ip_index, cidr_index)
        except Exception as exc:
            # The database may not exist yet (fresh checkout, unit test). File
            # indicators still work, so this is a debug note, not an error.
            log.debug("indicator table unavailable: %s", exc)

        cidr_index.sort(key=lambda item: item[0].prefixlen, reverse=True)
        _ip_index, _cidr_index = ip_index, cidr_index

        if ip_index or cidr_index:
            log.info("loaded %d IP and %d CIDR indicators", len(ip_index), len(cidr_index))
        return _ip_index, _cidr_index


def _index_value(
    value: str,
    source: str,
    ip_index: dict[str, set[str]],
    cidr_index: list[tuple[Any, str]],
) -> None:
    if not value:
        return
    try:
        if "/" in value:
            cidr_index.append((ipaddress.ip_network(value, strict=False), source))
        else:
            ipaddress.ip_address(value)  # validate
            ip_index.setdefault(value, set()).add(source)
    except ValueError:
        return


def reload_indicators() -> None:
    """Drop the cached indices so the next lookup re-reads from disk."""
    global _ip_index, _cidr_index
    with _lock:
        _ip_index = None
        _cidr_index = None


def refresh_from_file(path: Path, source: str, category: str = "generic") -> int:
    """Import indicators from a local file into the ``indicators`` table.

    Returns the number of new rows. Does not fetch anything over the network —
    the caller is responsible for putting the file on disk.
    """
    from sqlalchemy import select

    from storage.db import session_scope
    from storage.models import Indicator

    added = 0
    with session_scope() as db:
        for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            value = raw.split("#")[0].strip()
            if not value:
                continue
            try:
                kind = "cidr" if "/" in value else "ip"
                if kind == "cidr":
                    ipaddress.ip_network(value, strict=False)
                else:
                    ipaddress.ip_address(value)
            except ValueError:
                continue

            exists = db.execute(
                select(Indicator)
                .where(Indicator.kind == kind)
                .where(Indicator.value == value)
                .where(Indicator.source == source)
            ).scalar_one_or_none()
            if exists is not None:
                continue

            db.add(
                Indicator(
                    kind=kind,
                    value=value,
                    source=source,
                    category=category,
                    score=SCORE_EXACT_IP if kind == "ip" else SCORE_CIDR,
                )
            )
            added += 1

    reload_indicators()
    log.info("imported %d indicators from %s as source %r", added, path, source)
    return added


# --------------------------------------------------------------------------- #
# Lookups
# --------------------------------------------------------------------------- #


def check_ip(ip: str) -> dict[str, Any]:
    """Match an IP against the loaded indicator sets."""
    ip_index, cidr_index = _load_indices()
    tags: list[str] = []
    score = 0.0

    for source in sorted(ip_index.get(ip, ())):
        tags.append(source)
        score += SCORE_EXACT_IP

    if cidr_index:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        if addr is not None:
            for network, source in cidr_index:
                if addr.version == network.version and addr in network:
                    if source not in tags:
                        tags.append(source)
                        score += SCORE_CIDR
                    break  # longest prefix already won

    return {"ti_score": score, "ti_tags": tags}


def check_user_agent(user_agent: str | None) -> dict[str, Any]:
    """Classify a user-agent string using built-in heuristics."""
    if not user_agent:
        return {"ti_score": 0.0, "ti_tags": []}

    lowered = user_agent.lower()
    tags: list[str] = []
    score = 0.0

    for needle, tag in MALWARE_USER_AGENTS.items():
        if _matches_needle(lowered, needle):
            tags.append(tag)
            score += SCORE_MALWARE_UA

    for needle, tag in SCANNER_USER_AGENTS.items():
        if _matches_needle(lowered, needle):
            tags.append(tag)
            score += SCORE_SCANNER_UA

    # An empty or single-token UA on an HTTP request is a bot tell; browsers
    # always send something long and structured.
    if len(user_agent) < 8:
        tags.append("ua:suspiciously-short")
        score += 5.0

    return {"ti_score": score, "ti_tags": tags}


def check_username(username: str | None) -> dict[str, Any]:
    """Flag generic vs. targeted usernames."""
    if not username:
        return {"ti_score": 0.0, "ti_tags": []}
    if username.lower() in GENERIC_USERNAMES:
        return {"ti_score": 2.0, "ti_tags": ["cred:generic-username"]}
    return {"ti_score": 0.0, "ti_tags": ["cred:specific-username"]}


def enrich(
    ip: str,
    user_agent: str | None = None,
    username: str | None = None,
) -> dict[str, Any]:
    """Combine every available signal into one score and tag list."""
    results = [check_ip(ip), check_user_agent(user_agent), check_username(username)]
    tags: list[str] = []
    for result in results:
        for tag in result["ti_tags"]:
            if tag not in tags:
                tags.append(tag)
    return {
        "threat_score": round(sum(r["ti_score"] for r in results), 2),
        "threat_tags": tags,
    }


def indicator_stats() -> dict[str, int]:
    ip_index, cidr_index = _load_indices()
    return {
        "ip_indicators": len(ip_index),
        "cidr_indicators": len(cidr_index),
        "sources": len(
            {s for sources in ip_index.values() for s in sources} | {s for _, s in cidr_index}
        ),
    }


__all__ = [
    "check_ip",
    "check_user_agent",
    "check_username",
    "enrich",
    "refresh_from_file",
    "reload_indicators",
    "indicator_stats",
    "SCANNER_USER_AGENTS",
    "MALWARE_USER_AGENTS",
    "GENERIC_USERNAMES",
]
