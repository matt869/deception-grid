"""Engine / session management.

Defaults to SQLite so the stack runs with zero infrastructure, but honours
``DATABASE_URL`` for PostgreSQL in docker-compose.

SQLite needs deliberate tuning here. The honeypot writes continuously while the
API reads, and the default journal mode makes readers and the writer block each
other, which shows up as ``database is locked`` under even light load. WAL mode
plus a busy timeout fixes it.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import sessionmaker

from storage.models import Base

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "honeypot.db"

_engine: Engine | None = None
_SessionFactory: sessionmaker[OrmSession] | None = None


def database_url() -> str:
    """Resolve the database URL from the environment, defaulting to SQLite."""
    url = os.getenv("DATABASE_URL", "").strip()
    if url:
        return url
    DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{DEFAULT_DB_PATH.as_posix()}"


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def get_engine(url: str | None = None, echo: bool = False) -> Engine:
    """Return the process-wide engine, creating it on first use."""
    global _engine, _SessionFactory
    if _engine is not None and url is None:
        return _engine

    resolved = url or database_url()
    kwargs: dict = {"echo": echo, "future": True}

    if _is_sqlite(resolved):
        # check_same_thread=False: the honeypot's writer thread and the API's
        # request threads share the engine's pool.
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
    else:
        kwargs["pool_pre_ping"] = True
        kwargs["pool_size"] = 10
        kwargs["max_overflow"] = 20

    engine = create_engine(resolved, **kwargs)

    if _is_sqlite(resolved):

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - driver hook
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA busy_timeout=30000")
            cur.close()

    if url is None:
        _engine = engine
        _SessionFactory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    return engine


def get_session_factory() -> sessionmaker[OrmSession]:
    global _SessionFactory
    if _SessionFactory is None:
        get_engine()
    assert _SessionFactory is not None
    return _SessionFactory


@contextmanager
def session_scope() -> Iterator[OrmSession]:
    """Transactional scope. Commits on success, rolls back on any exception."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[OrmSession]:
    """FastAPI dependency. Read-mostly, so it does not auto-commit."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()


def init_db(engine: Engine | None = None, drop: bool = False) -> Engine:
    """Create all tables (and optionally drop them first)."""
    eng = engine or get_engine()
    if drop:
        Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)
    _apply_migrations(eng)
    return eng


def _apply_migrations(engine: Engine) -> None:
    """Run the ordered .sql files in ``storage/migrations``.

    A deliberately small substitute for Alembic: this schema is append-only and
    recreatable from raw events, so full migration machinery would cost more
    than it returns. Applied filenames are tracked in ``schema_migrations``.
    """
    migrations_dir = Path(__file__).resolve().parent / "migrations"
    if not migrations_dir.is_dir():
        return

    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "  filename VARCHAR(255) PRIMARY KEY,"
                "  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
            )
        )
        applied = {row[0] for row in conn.execute(text("SELECT filename FROM schema_migrations"))}

        for path in sorted(migrations_dir.glob("*.sql")):
            if path.name in applied:
                continue
            sql = path.read_text(encoding="utf-8")
            for statement in _split_statements(sql):
                conn.execute(text(statement))
            conn.execute(
                text("INSERT INTO schema_migrations (filename) VALUES (:f)"),
                {"f": path.name},
            )


def _split_statements(sql: str) -> list[str]:
    """Split a .sql file into statements, ignoring comments and blank lines."""
    out: list[str] = []
    for chunk in sql.split(";"):
        lines = [
            ln for ln in chunk.splitlines() if ln.strip() and not ln.strip().startswith("--")
        ]
        statement = "\n".join(lines).strip()
        if statement:
            out.append(statement)
    return out


def reset_state() -> None:
    """Drop cached engine/factory. Used by tests that swap databases."""
    global _engine, _SessionFactory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionFactory = None


__all__ = [
    "get_engine",
    "get_session_factory",
    "session_scope",
    "get_db",
    "init_db",
    "database_url",
    "reset_state",
]
