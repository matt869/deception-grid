"""Docker Engine API emulator.

An unauthenticated Docker socket bound to TCP 2375 is one of the highest-value
targets on the internet, because it is not an exploit — it is the documented API
working exactly as designed. Anyone who can reach it can create a container that
bind-mounts the host filesystem and, from inside it, read or write anything on
the host as root. No CVE, no memory corruption, no privilege escalation needed.

That makes it worth emulating carefully. The interesting capture is not the
recon (``/version``, ``/info``, ``/containers/json`` — every scanner does that),
it is the JSON body of ``POST /containers/create``: the image the operator
chose, the command they intended to run, and above all the ``HostConfig.Binds``
list, which states in plain text what they were trying to reach. A body
containing ``"/:/mnt"`` is an unambiguous host-takeover attempt.

The service speaks just enough HTTP/1.1 to keep that sequence progressing —
a plausible ``/version``, an empty container list, and a fabricated 201 with a
container ID so the client proceeds to ``/start`` and ``/exec`` and reveals the
whole plan. Nothing is created, pulled, started or executed.
"""

from __future__ import annotations

import asyncio
import json
import re

from honeypot.services.base import BaseService
from honeypot.session import HoneypotSession
from storage.models import EventType, Severity

MAX_HEADERS = 64
MAX_BODY_BYTES = 64 * 1024
MAX_REQUESTS = 50

# A fabricated but well-formed 64-hex container ID. Stable per response so a
# client that creates then starts then inspects sees a consistent object.
FAKE_CONTAINER_ID = "3f2b9c14a7e85d60b1c4f83a2d97e0561f8b4c3a29d70e6b5a1c8f42d3e9b7a0"
FAKE_IMAGE_ID = "sha256:6b7f2e51c9a34d80e5f1b2c7a9d3e4f801a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"

# Endpoints worth distinguishing. Ordered most-specific first.
ROUTES: list[tuple[str, re.Pattern[str]]] = [
    ("containers-create", re.compile(r"^/(v[\d.]+/)?containers/create", re.I)),
    ("containers-start", re.compile(r"^/(v[\d.]+/)?containers/[^/]+/start", re.I)),
    ("containers-exec", re.compile(r"^/(v[\d.]+/)?containers/[^/]+/exec", re.I)),
    ("exec-start", re.compile(r"^/(v[\d.]+/)?exec/[^/]+/start", re.I)),
    ("containers-list", re.compile(r"^/(v[\d.]+/)?containers/json", re.I)),
    ("images-create", re.compile(r"^/(v[\d.]+/)?images/create", re.I)),
    ("images-list", re.compile(r"^/(v[\d.]+/)?images/json", re.I)),
    ("version", re.compile(r"^/(v[\d.]+/)?version", re.I)),
    ("info", re.compile(r"^/(v[\d.]+/)?info", re.I)),
    ("ping", re.compile(r"^/(v[\d.]+/)?_ping", re.I)),
]

# Bind sources that mean "give me the host". Anything mounting the root, the
# Docker socket itself, or a sensitive host directory is a takeover attempt.
DANGEROUS_BINDS = re.compile(
    r"(^|[\"'\s])(/|/etc|/root|/home|/var/run/docker\.sock|/proc|/sys)(:|/[^:]*:)", re.I
)

# Images that are almost never benign on an exposed daemon.
SUSPECT_IMAGE = re.compile(r"(xmrig|monero|miner|kinsing|cryptonight|watchbog|kaiten)", re.I)


class DockerService(BaseService):
    name = "docker"

    async def handle_session(
        self,
        session: HoneypotSession,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        for _ in range(MAX_REQUESTS):
            request = await self._read_request(session, reader)
            if request is None:
                return
            method, path, headers, body = request

            route = self._classify(path)
            tags, severity = self._assess(route, body)

            recorded = session.record(
                EventType.HTTP_REQUEST,
                severity=severity,
                http_method=method,
                path=path,
                user_agent=headers.get("user-agent"),
                headers={k: v[:256] for k, v in list(headers.items())[:24]},
                status_code=self._status_for(route),
                payload_size=len(body),
                command=body.decode("utf-8", "replace")[:2048] if body else None,
                tags=tags,
                extra={"docker_route": route},
            )
            if not recorded:
                return

            await self.send(writer, self._respond(route, path))

            if headers.get("connection", "").lower() == "close":
                return

    # ------------------------------------------------------------------ #

    async def _read_request(
        self, session: HoneypotSession, reader: asyncio.StreamReader
    ) -> tuple[str, str, dict[str, str], bytes] | None:
        """Read one HTTP request. None on EOF, timeout or an unusable request line."""
        line = await self.read_line(session, reader)
        if line is None:
            return None
        parts = line.split()
        if len(parts) < 2:
            return None
        method, path = parts[0][:16], parts[1][:2048]

        headers: dict[str, str] = {}
        for _ in range(MAX_HEADERS):
            header = await self.read_line(session, reader)
            if header is None or header == "":
                break
            name, _, value = header.partition(":")
            if name:
                headers[name.strip().lower()] = value.strip()

        # Content-Length is an attacker's claim, not a fact — cap before reading.
        body = b""
        try:
            declared = int(headers.get("content-length", "0"))
        except ValueError:
            declared = 0
        if declared > 0:
            body = await self.read_bytes(session, reader, min(declared, MAX_BODY_BYTES))

        return method, path, headers, body

    def _classify(self, path: str) -> str:
        for label, pattern in ROUTES:
            if pattern.match(path):
                return label
        return "other"

    def _assess(self, route: str, body: bytes) -> tuple[list[str], Severity]:
        """Tag and score one request.

        The severity ladder is about intent, not noise: enumerating the daemon is
        reconnaissance, but a create call carrying a host bind is the point at
        which a real host would already be lost.
        """
        tags = ["docker-api"]
        severity = Severity.LOW

        if route in ("ping", "version", "info", "containers-list", "images-list"):
            tags.append("docker-recon")
            severity = Severity.MEDIUM  # an exposed daemon being enumerated is never routine
            return tags, severity

        text = body.decode("utf-8", "replace") if body else ""

        if route == "containers-create":
            tags += ["docker-container-create", "docker-abuse"]
            severity = Severity.HIGH
            if DANGEROUS_BINDS.search(text):
                tags += ["docker-host-mount", "docker-host-takeover"]
                severity = Severity.CRITICAL
            if _privileged(text):
                tags.append("docker-privileged")
                severity = Severity.CRITICAL
            if SUSPECT_IMAGE.search(text):
                tags.append("docker-cryptominer")
                severity = Severity.CRITICAL
        elif route == "images-create":
            tags += ["docker-image-pull", "docker-abuse"]
            severity = Severity.HIGH
            if SUSPECT_IMAGE.search(text):
                tags.append("docker-cryptominer")
                severity = Severity.CRITICAL
        elif route in ("containers-start", "containers-exec", "exec-start"):
            tags += ["docker-execute", "docker-abuse"]
            severity = Severity.CRITICAL
        else:
            tags.append("docker-probe")

        return tags, severity

    def _status_for(self, route: str) -> int:
        if route == "containers-create":
            return 201
        if route in ("containers-start", "exec-start"):
            return 204
        if route == "other":
            return 404
        return 200

    def _respond(self, route: str, path: str) -> str:
        if route == "ping":
            return _http(200, "OK", content_type="text/plain")
        if route == "version":
            return _http(200, json.dumps(_VERSION))
        if route == "info":
            return _http(200, json.dumps(_INFO))
        if route in ("containers-list", "images-list"):
            return _http(200, "[]")
        if route == "containers-create":
            return _http(201, json.dumps({"Id": FAKE_CONTAINER_ID, "Warnings": []}))
        if route == "containers-exec":
            return _http(201, json.dumps({"Id": FAKE_CONTAINER_ID[:32]}))
        if route in ("containers-start", "exec-start"):
            return _http(204, "")
        if route == "images-create":
            # Docker streams newline-delimited JSON progress for a pull.
            stream = (
                json.dumps({"status": "Pulling from library/alpine", "id": "latest"})
                + "\r\n"
                + json.dumps({"status": "Download complete", "id": "31e352740f53"})
                + "\r\n"
                + json.dumps({"status": f"Status: Downloaded newer image for {FAKE_IMAGE_ID[:24]}"})
                + "\r\n"
            )
            return _http(200, stream)
        return _http(404, json.dumps({"message": "page not found"}))


def _privileged(text: str) -> bool:
    """True when the create body asks for a privileged container."""
    try:
        payload = json.loads(text) if text.strip().startswith("{") else {}
    except (ValueError, TypeError):
        # Malformed JSON is still worth flagging on the raw text.
        return '"Privileged": true' in text or '"Privileged":true' in text
    host_config = payload.get("HostConfig") or {}
    return bool(host_config.get("Privileged")) or bool(host_config.get("PidMode") == "host")


def _http(status: int, body: str, content_type: str = "application/json") -> str:
    reason = {200: "OK", 201: "Created", 204: "No Content", 404: "Not Found"}.get(status, "OK")
    headers = [
        f"HTTP/1.1 {status} {reason}",
        f"Api-Version: {_VERSION['ApiVersion']}",
        "Docker-Experimental: false",
        "Ostype: linux",
        f"Server: Docker/{_VERSION['Version']} (linux)",
    ]
    if status == 204:
        headers.append("Connection: keep-alive")
        return "\r\n".join(headers) + "\r\n\r\n"
    headers += [
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body.encode('utf-8'))}",
    ]
    return "\r\n".join(headers) + "\r\n\r\n" + body


_VERSION = {
    "Platform": {"Name": "Docker Engine - Community"},
    "Version": "24.0.7",
    "ApiVersion": "1.43",
    "MinAPIVersion": "1.12",
    "GitCommit": "311b9ff",
    "GoVersion": "go1.20.10",
    "Os": "linux",
    "Arch": "amd64",
    "KernelVersion": "5.15.0-91-generic",
    "BuildTime": "2023-10-26T09:08:01.000000000+00:00",
}

_INFO = {
    "ID": "4a7b2c19-8e3f-4d51-9c06-2f8a1b7d3e94",
    "Containers": 0,
    "ContainersRunning": 0,
    "ContainersPaused": 0,
    "ContainersStopped": 0,
    "Images": 3,
    "Driver": "overlay2",
    "MemoryLimit": True,
    "SwapLimit": False,
    "CpuCfsPeriod": True,
    "KernelVersion": "5.15.0-91-generic",
    "OperatingSystem": "Ubuntu 22.04.3 LTS",
    "OSType": "linux",
    "Architecture": "x86_64",
    "NCPU": 2,
    "MemTotal": 4106125312,
    "DockerRootDir": "/var/lib/docker",
    "ServerVersion": "24.0.7",
    "SecurityOptions": ["name=apparmor", "name=seccomp,profile=builtin"],
}


__all__ = ["DockerService", "DANGEROUS_BINDS", "FAKE_CONTAINER_ID"]
