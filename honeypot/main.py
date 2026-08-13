"""Honeypot entry point.

    python -m honeypot.main                    # all enabled services
    python -m honeypot.main --only telnet,http # a subset
    python -m honeypot.main --list-personas

Starts one asyncio server per enabled service, plus a background writer thread
for events, and blocks until interrupted.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys

from honeypot.config import Settings, load_settings
from honeypot.deception.banners import list_personas
from honeypot.logger import EventLogger, configure_logging
from honeypot.services import SERVICE_REGISTRY
from honeypot.session import SessionRegistry

log = logging.getLogger("honeypot.main")

STATS_INTERVAL_S = 60


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeypot",
        description="Multi-service honeypot sensor",
    )
    parser.add_argument(
        "--only",
        help="comma-separated services to run (ssh,telnet,ftp,http); default is all enabled",
    )
    parser.add_argument("--persona", help="override HONEYPOT_PERSONA for this run")
    parser.add_argument("--bind", help="override the bind address")
    parser.add_argument("--log-level", default=None, help="DEBUG, INFO, WARNING, ERROR")
    parser.add_argument(
        "--no-db", action="store_true", help="write JSONL only, skip the database"
    )
    parser.add_argument("--list-personas", action="store_true", help="print personas and exit")
    parser.add_argument(
        "--check", action="store_true", help="validate configuration and exit without listening"
    )
    return parser


class Honeypot:
    """Owns the service listeners and their shared state."""

    def __init__(self, settings: Settings, only: list[str] | None = None) -> None:
        self.settings = settings
        self.logger = EventLogger(settings)
        self.registry = SessionRegistry(settings)
        self.services = []
        self._stop = asyncio.Event()

        for service_config in settings.enabled_services():
            if only and service_config.name not in only:
                continue
            implementation = SERVICE_REGISTRY.get(service_config.name)
            if implementation is None:  # pragma: no cover - guarded by config.validate
                log.warning("no implementation for service %r; skipping", service_config.name)
                continue
            self.services.append(
                implementation(settings, self.logger, self.registry, service_config.port)
            )

        if not self.services:
            raise SystemExit("no services selected; check --only and *_ENABLED settings")

    async def run(self) -> None:
        self.logger.start()

        started = []
        try:
            for service in self.services:
                await service.start()
                started.append(service)
        except OSError as exc:
            # Almost always "port already in use" or "permission denied" on a
            # low port. Say which, rather than dumping a bare errno.
            log.error("could not bind: %s", exc)
            for service in started:
                await service.stop()
            self.logger.stop()
            raise SystemExit(1) from exc

        log.info(
            "sensor %r up as persona %r (%s) — %d service(s)",
            self.settings.sensor_name,
            self.settings.persona,
            self.settings.hostname,
            len(self.services),
        )

        stats_task = asyncio.create_task(self._report_stats())
        try:
            await self._stop.wait()
        finally:
            stats_task.cancel()
            for service in self.services:
                await service.stop()
            self.logger.stop()

    async def _report_stats(self) -> None:
        while True:
            try:
                await asyncio.sleep(STATS_INTERVAL_S)
            except asyncio.CancelledError:
                return
            stats = {**self.registry.stats(), **self.logger.stats()}
            log.info(
                "active=%(active_sessions)d ips=%(active_ips)d accepted=%(total_accepted)d "
                "written=%(written)d queued=%(queued)d dropped=%(dropped)d "
                "rejected=%(rejected_global)d/%(rejected_per_ip)d",
                stats,
            )

    def request_stop(self) -> None:
        self._stop.set()


async def async_main(args: argparse.Namespace) -> int:
    settings = load_settings()

    if args.persona:
        settings.persona = args.persona
    if args.bind:
        settings.bind_host = args.bind
    if args.no_db:
        settings.write_to_db = False
    settings.validate()

    if settings.write_to_db:
        from storage.db import init_db

        init_db()

    only = None
    if args.only:
        only = [name.strip().lower() for name in args.only.split(",") if name.strip()]
        unknown = set(only) - set(SERVICE_REGISTRY)
        if unknown:
            log.error("unknown service(s): %s", ", ".join(sorted(unknown)))
            return 2

    honeypot = Honeypot(settings, only=only)

    loop = asyncio.get_running_loop()
    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, honeypot.request_stop)
        except NotImplementedError:
            # Windows ProactorEventLoop does not support add_signal_handler;
            # the KeyboardInterrupt handler in main() covers Ctrl+C there.
            pass

    await honeypot.run()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_personas:
        for persona in list_personas():
            print(f"{persona['key']:<18} {persona['description']}")
        return 0

    configure_logging(args.log_level or "INFO")

    if args.check:
        settings = load_settings()
        print(f"configuration OK — sensor={settings.sensor_name} persona={settings.persona}")
        for service in settings.enabled_services():
            print(f"  {service.name:<8} {settings.bind_host}:{service.port}")
        return 0

    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        log.info("interrupted; shutting down")
        return 0


if __name__ == "__main__":
    sys.exit(main())
