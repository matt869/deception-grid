"""Drop and recreate the schema.

    python -m tools.reset_db --yes
    python -m tools.reset_db --events-only --older-than 30

Destructive. Requires ``--yes`` or an interactive confirmation, and prints what
it is about to destroy first — a honeypot dataset is not reproducible, so an
accidental wipe loses observations that cannot be collected again.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from typing import Optional

from sqlalchemy import delete, func, select

from storage.db import database_url, get_engine, init_db, session_scope
from storage.models import Alert, Attacker, Base, Event, Indicator, Session, utcnow


def current_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    try:
        with session_scope() as db:
            for name, model in (
                ("events", Event), ("sessions", Session),
                ("attackers", Attacker), ("alerts", Alert), ("indicators", Indicator),
            ):
                counts[name] = int(db.execute(select(func.count()).select_from(model)).scalar_one())
    except Exception:
        # Tables may not exist yet, which is a fine state to reset from.
        pass
    return counts


def confirm(prompt: str) -> bool:
    try:
        return input(f"{prompt} [type 'yes' to confirm]: ").strip().lower() == "yes"
    except (EOFError, KeyboardInterrupt):
        return False


def drop_everything() -> None:
    engine = get_engine()
    Base.metadata.drop_all(engine)
    # The migration ledger lives outside the ORM metadata, so drop it explicitly
    # or the recreated schema thinks migrations already ran.
    with engine.begin() as conn:
        from sqlalchemy import text

        conn.execute(text("DROP TABLE IF EXISTS schema_migrations"))
    init_db()


def purge_events(older_than_days: float) -> dict[str, int]:
    """Delete events older than N days, then rebuild the derived tables."""
    cutoff = utcnow() - dt.timedelta(days=older_than_days)
    removed: dict[str, int] = {}

    with session_scope() as db:
        result = db.execute(delete(Event).where(Event.ts < cutoff))
        removed["events"] = result.rowcount or 0
        result = db.execute(delete(Session).where(Session.started_at < cutoff))
        removed["sessions"] = result.rowcount or 0
        result = db.execute(delete(Alert).where(Alert.last_seen < cutoff))
        removed["alerts"] = result.rowcount or 0

    # Attackers is a pure aggregate; rebuild rather than delete-by-date, or its
    # counters would still include the events we just removed.
    with session_scope() as db:
        db.execute(delete(Attacker))
    with session_scope() as db:
        from storage import queries

        removed["attackers_rebuilt"] = queries.rebuild_attackers(db)

    return removed


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Reset or prune the honeypot database")
    parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    parser.add_argument(
        "--events-only", action="store_true",
        help="prune old events instead of dropping the schema (needs --older-than)",
    )
    parser.add_argument(
        "--older-than", type=float, metavar="DAYS",
        help="with --events-only, delete data older than this many days",
    )
    args = parser.parse_args(argv)

    url = database_url()
    counts = current_counts()

    print(f"database: {url}")
    if counts:
        print("current contents:")
        for name, count in counts.items():
            print(f"  {name:<12} {count:>10,}")
    else:
        print("  (no tables yet)")

    if args.events_only:
        if args.older_than is None:
            print("\n--events-only requires --older-than DAYS", file=sys.stderr)
            return 2
        action = f"delete all data older than {args.older_than:g} days"
    else:
        action = "DROP AND RECREATE every table"

    print(f"\nabout to: {action}")

    if not args.yes and not confirm("proceed?"):
        print("aborted; nothing changed")
        return 1

    if args.events_only:
        removed = purge_events(args.older_than)
        print("\nremoved:")
        for name, count in removed.items():
            print(f"  {name:<20} {count:>10,}")
    else:
        drop_everything()
        print("\nschema dropped and recreated; database is empty")

    return 0


if __name__ == "__main__":
    sys.exit(main())
