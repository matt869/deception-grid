"""Group attackers into campaigns by behaviour rather than by address.

    python -m pipeline.analysis.campaigns
    python -m pipeline.analysis.campaigns --threshold 0.45 --json

An IP-keyed view structurally cannot answer "is this the same operator from a
new address?", and that is the question that matters: botnet operators rotate
through compromised hosts constantly, so counting unique source IPs measures
the size of somebody's botnet, not the number of adversaries.

**How, and why this way.** Each source becomes a set of behavioural facets —
credentials tried, paths requested, artefacts delivered, tooling tags. Two
sources are compared with a weighted Jaccard overlap of those facets, and
anything above the threshold is joined into the same campaign by union-find.

Three deliberate choices:

*Interpretable over clever.* Set overlap, not an embedding. An analyst can be
shown exactly which credentials two addresses share, and disagree with the
grouping. A cosine distance between two vectors nobody can read is not evidence.

*Connected components, not k-means.* Nobody knows how many campaigns are in a
capture, and campaigns are wildly uneven in size. Requiring a ``k`` up front
invents an answer.

*Discriminative facets are weighted; ambient ones are not.* Sharing "ssh" is
worthless — everything on the internet touches port 22. Sharing an exact
credential pair, a payload hash, or a distinctive request path is strong. Weight
this wrong and you get one giant cluster containing the whole internet, which is
the failure mode this module is most careful about.

Nothing here reaches the network, and clustering is computed from data already
in the database.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

# Facet weights. Credentials and artefacts identify an operator's toolkit;
# services and country are ambient properties of the internet. A shared payload
# hash is near-conclusive: the same bytes from two addresses is one operator.
FACET_WEIGHTS: dict[str, float] = {
    "payloads": 3.0,
    "credentials": 2.5,
    "paths": 1.5,
    "usernames": 1.0,
    "tags": 1.0,
    "services": 0.25,
}

DEFAULT_THRESHOLD = 0.35
MIN_CAMPAIGN_SIZE = 2  # a campaign of one is just an attacker


@dataclass(frozen=True)
class Fingerprint:
    """One source's behaviour, reduced to comparable sets."""

    src_ip: str
    usernames: frozenset[str] = frozenset()
    credentials: frozenset[str] = frozenset()
    paths: frozenset[str] = frozenset()
    services: frozenset[str] = frozenset()
    tags: frozenset[str] = frozenset()
    payloads: frozenset[str] = frozenset()
    asn: int | None = None
    country: str | None = None
    classification: str | None = None
    event_count: int = 0
    first_seen: Any = None
    last_seen: Any = None

    def facet(self, name: str) -> frozenset[str]:
        return getattr(self, name)

    @property
    def is_empty(self) -> bool:
        """True when nothing discriminative was observed.

        A source that only ever connected and disconnected has no behaviour to
        compare. Clustering those together would produce one enormous "campaign"
        of every port scanner on the internet, which is worse than saying
        nothing.
        """
        return not (self.credentials or self.paths or self.payloads or self.usernames)


def fingerprint_attacker(
    attacker,
    payload_hashes: Iterable[str] = (),
    credential_pairs: Iterable[str] = (),
) -> Fingerprint:
    """Build a :class:`Fingerprint` from an ``Attacker`` row.

    ``credential_pairs`` must be pairs actually observed together, as
    ``"user:pass"``. They are passed in rather than derived from the attacker
    aggregate because that row stores top usernames and top passwords as two
    separate lists — combining them here would invent pairs nobody ever tried,
    and a campaign that cites a credential as evidence has to be citing one that
    was really used. :func:`build_fingerprints` reads the real pairs from events.
    """
    usernames = [u for u in (attacker.top_usernames or []) if u]
    credentials = {c for c in credential_pairs if c}

    return Fingerprint(
        src_ip=attacker.src_ip,
        usernames=frozenset(usernames),
        credentials=frozenset(credentials),
        paths=frozenset(p for p in (attacker.top_paths or []) if p),
        services=frozenset(attacker.services or []),
        tags=frozenset(t for t in (attacker.tags or []) if t),
        payloads=frozenset(payload_hashes),
        asn=attacker.asn,
        country=attacker.country,
        classification=attacker.classification,
        event_count=attacker.event_count or 0,
        first_seen=attacker.first_seen,
        last_seen=attacker.last_seen,
    )


def jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    """Overlap of two sets, 0.0–1.0. Two empty sets share nothing, not everything."""
    if not a or not b:
        return 0.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


def similarity(left: Fingerprint, right: Fingerprint) -> float:
    """Weighted overlap across every facet both sources actually have.

    The denominator counts only facets where at least one side has data, so a
    source with no recorded paths is not penalised for it — otherwise every
    sparse fingerprint would score near zero and nothing would ever cluster.
    """
    total = 0.0
    weight_sum = 0.0
    for facet, weight in FACET_WEIGHTS.items():
        a, b = left.facet(facet), right.facet(facet)
        if not a and not b:
            continue  # neither observed: carries no information either way
        weight_sum += weight
        total += weight * jaccard(a, b)
    return total / weight_sum if weight_sum else 0.0


class _UnionFind:
    """Union-find over fingerprint indices."""

    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]  # path halving
            i = self.parent[i]
        return i

    def union(self, i: int, j: int) -> None:
        ri, rj = self.find(i), self.find(j)
        if ri != rj:
            self.parent[max(ri, rj)] = min(ri, rj)


@dataclass
class Campaign:
    """A group of sources judged to be one operator."""

    members: list[str]
    shared_credentials: list[str] = field(default_factory=list)
    shared_payloads: list[str] = field(default_factory=list)
    shared_paths: list[str] = field(default_factory=list)
    asns: list[int] = field(default_factory=list)
    countries: list[str] = field(default_factory=list)
    classifications: list[str] = field(default_factory=list)
    event_count: int = 0
    cohesion: float = 0.0
    first_seen: Any = None
    last_seen: Any = None

    @property
    def size(self) -> int:
        return len(self.members)

    def as_dict(self) -> dict[str, Any]:
        return {
            "size": self.size,
            "members": self.members,
            "event_count": self.event_count,
            "cohesion": round(self.cohesion, 3),
            "shared_credentials": self.shared_credentials,
            "shared_payloads": self.shared_payloads,
            "shared_paths": self.shared_paths,
            "asns": self.asns,
            "countries": self.countries,
            "classifications": self.classifications,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


def _summarise(group: list[Fingerprint], scores: list[float]) -> Campaign:
    """Describe one cluster, including *why* its members were grouped."""
    shared_credentials = set.intersection(*[set(f.credentials) for f in group])
    shared_payloads = set.intersection(*[set(f.payloads) for f in group])
    shared_paths = set.intersection(*[set(f.paths) for f in group])

    firsts = [f.first_seen for f in group if f.first_seen]
    lasts = [f.last_seen for f in group if f.last_seen]

    return Campaign(
        members=sorted(f.src_ip for f in group),
        shared_credentials=sorted(shared_credentials)[:20],
        shared_payloads=sorted(shared_payloads)[:20],
        shared_paths=sorted(shared_paths)[:20],
        asns=sorted({f.asn for f in group if f.asn is not None}),
        countries=sorted({f.country for f in group if f.country}),
        classifications=sorted({f.classification for f in group if f.classification}),
        event_count=sum(f.event_count for f in group),
        cohesion=(sum(scores) / len(scores)) if scores else 0.0,
        first_seen=min(firsts) if firsts else None,
        last_seen=max(lasts) if lasts else None,
    )


def cluster(
    fingerprints: list[Fingerprint],
    *,
    threshold: float = DEFAULT_THRESHOLD,
    min_size: int = MIN_CAMPAIGN_SIZE,
) -> list[Campaign]:
    """Group fingerprints into campaigns, largest first.

    Sources with no discriminative behaviour are dropped before comparison
    rather than clustered — see :attr:`Fingerprint.is_empty`.
    """
    usable = [f for f in fingerprints if not f.is_empty]
    if len(usable) < 2:
        return []

    uf = _UnionFind(len(usable))
    edge_scores: dict[tuple[int, int], float] = {}

    for i in range(len(usable)):
        for j in range(i + 1, len(usable)):
            score = similarity(usable[i], usable[j])
            if score >= threshold:
                uf.union(i, j)
                edge_scores[(i, j)] = score

    groups: dict[int, list[int]] = {}
    for index in range(len(usable)):
        groups.setdefault(uf.find(index), []).append(index)

    campaigns: list[Campaign] = []
    for indices in groups.values():
        if len(indices) < min_size:
            continue
        members = set(indices)
        scores = [s for (i, j), s in edge_scores.items() if i in members and j in members]
        campaigns.append(_summarise([usable[i] for i in indices], scores))

    campaigns.sort(key=lambda c: (c.size, c.event_count), reverse=True)
    return campaigns


# --------------------------------------------------------------------------- #
# Database entry point
# --------------------------------------------------------------------------- #


def build_fingerprints(db, limit: int = 2000) -> list[Fingerprint]:
    """Fingerprint the top attackers, with the artefacts each one delivered."""
    from sqlalchemy import select

    from storage import queries
    from storage.models import Event

    attackers, _ = queries.list_attackers(db, limit=limit, sort="event_count")
    if not attackers:
        return []

    # Two grouped queries for the whole set, rather than two per source.
    ips = [a.src_ip for a in attackers]

    payloads_by_ip: dict[str, set[str]] = {}
    for src_ip, sha in db.execute(
        select(Event.src_ip, Event.payload_sha256)
        .where(Event.payload_sha256.is_not(None))
        .where(Event.src_ip.in_(ips))
        .distinct()
    ):
        payloads_by_ip.setdefault(src_ip, set()).add(sha)

    # Real credential pairs, as observed on a single event. See the note in
    # fingerprint_attacker about why these cannot come from the aggregate.
    creds_by_ip: dict[str, set[str]] = {}
    for src_ip, username, password in db.execute(
        select(Event.src_ip, Event.username, Event.password)
        .where(Event.username.is_not(None))
        .where(Event.password.is_not(None))
        .where(Event.src_ip.in_(ips))
        .distinct()
    ):
        creds_by_ip.setdefault(src_ip, set()).add(f"{username}:{password}")

    return [
        fingerprint_attacker(
            a, payloads_by_ip.get(a.src_ip, set()), creds_by_ip.get(a.src_ip, set())
        )
        for a in attackers
    ]


def find_campaigns(
    db,
    *,
    threshold: float = DEFAULT_THRESHOLD,
    limit: int = 2000,
    min_size: int = MIN_CAMPAIGN_SIZE,
) -> list[Campaign]:
    """Fingerprint and cluster in one call."""
    return cluster(build_fingerprints(db, limit=limit), threshold=threshold, min_size=min_size)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    parser = argparse.ArgumentParser(description="Group attackers into campaigns by behaviour.")
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help=f"similarity floor, 0-1 (default {DEFAULT_THRESHOLD})",
    )
    parser.add_argument("--limit", type=int, default=2000, help="attackers to consider")
    parser.add_argument("--min-size", type=int, default=MIN_CAMPAIGN_SIZE)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    from storage.db import session_scope

    with session_scope() as db:
        campaigns = find_campaigns(
            db, threshold=args.threshold, limit=args.limit, min_size=args.min_size
        )

    if args.json:
        print(json.dumps([c.as_dict() for c in campaigns], indent=2, default=str))
        return 0

    if not campaigns:
        print("no campaigns found above the threshold", file=sys.stderr)
        return 0

    grouped = sum(c.size for c in campaigns)
    print(f"{len(campaigns)} campaign(s) covering {grouped} sources\n")
    for n, c in enumerate(campaigns, 1):
        print(
            f"campaign {n}: {c.size} sources, {c.event_count:,} events, cohesion {c.cohesion:.2f}"
        )
        print(f"  members   : {', '.join(c.members[:8])}{' …' if c.size > 8 else ''}")
        if c.classifications:
            print(f"  class     : {', '.join(c.classifications)}")
        if c.asns:
            print(f"  ASNs      : {', '.join(str(a) for a in c.asns[:8])}")
        if c.countries:
            print(f"  countries : {', '.join(c.countries[:8])}")
        if c.shared_credentials:
            print(f"  shared creds : {', '.join(c.shared_credentials[:5])}")
        if c.shared_payloads:
            print(f"  shared bytes : {', '.join(s[:12] for s in c.shared_payloads[:4])}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = [
    "Fingerprint",
    "Campaign",
    "fingerprint_attacker",
    "similarity",
    "jaccard",
    "cluster",
    "find_campaigns",
    "build_fingerprints",
    "FACET_WEIGHTS",
    "DEFAULT_THRESHOLD",
]
