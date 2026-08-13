"""HTTP emulator.

Parses HTTP/1.1 by hand rather than mounting a web framework, for two reasons:
a framework normalises away exactly the malformed requests that are most
interesting, and its error pages fingerprint it instantly.

Requests are classified against a set of recognisable attack patterns —
traversal, SQL injection, shell injection in headers (Shellshock), JNDI lookups
(Log4Shell), webshell uploads — and tagged so the detection pipeline and the
dashboard can group a campaign without re-parsing raw paths.

The parser is the most exposed code in the project. Everything it reads is
length-capped before allocation: a ``Content-Length`` header is a claim by an
attacker, not a fact.
"""

from __future__ import annotations

import asyncio
import re
from typing import Optional
from urllib.parse import parse_qs, unquote_plus

from honeypot.deception.responses import http_response_for
from honeypot.services.base import BaseService
from honeypot.session import HoneypotSession
from storage.models import EventType, Severity

MAX_HEADERS = 64
MAX_BODY_BYTES = 64 * 1024

# (tag, severity, compiled pattern). Ordered most-specific first; a request can
# match several and collects every tag.
ATTACK_PATTERNS: list[tuple[str, Severity, re.Pattern[str]]] = [
    ("log4shell", Severity.CRITICAL, re.compile(r"\$\{jndi:(ldap|rmi|dns|iiop)", re.I)),
    ("shellshock", Severity.CRITICAL, re.compile(r"\(\s*\)\s*\{.*;\s*\}\s*;", re.S)),
    ("path-traversal", Severity.HIGH, re.compile(r"(\.\./|\.\.\\|%2e%2e[/\\%])", re.I)),
    ("sql-injection", Severity.HIGH, re.compile(
        r"(\bunion\b[\s/*]+\bselect\b|'\s*or\s*'?1'?\s*=\s*'?1|\bsleep\s*\(\d|"
        r"\bbenchmark\s*\(|information_schema)", re.I)),
    ("command-injection", Severity.HIGH, re.compile(
        r"(;|\||`|\$\()\s*(cat|wget|curl|nc|bash|sh|python|perl)\b", re.I)),
    ("webshell-upload", Severity.CRITICAL, re.compile(
        r"\.(php|jsp|asp|aspx|phtml)[\d]?($|\?|;)", re.I)),
    ("xss-probe", Severity.MEDIUM, re.compile(r"(<script|javascript:|onerror\s*=)", re.I)),
    ("env-file-probe", Severity.HIGH, re.compile(r"/\.(env|git|aws|ssh|svn)(/|$)", re.I)),
    ("cgi-probe", Severity.MEDIUM, re.compile(r"/cgi-bin/", re.I)),
    ("admin-probe", Severity.LOW, re.compile(
        r"/(wp-admin|wp-login|phpmyadmin|admin|manager/html|solr|actuator)", re.I)),
]

CREDENTIAL_FIELDS = ("username", "user", "usr", "login", "email", "log", "pwd", "password", "pass")


class ParsedRequest:
    __slots__ = ("method", "path", "version", "headers", "body", "malformed")

    def __init__(self) -> None:
        self.method: str = ""
        self.path: str = ""
        self.version: str = ""
        self.headers: dict[str, str] = {}
        self.body: bytes = b""
        self.malformed: Optional[str] = None


class HTTPService(BaseService):
    name = "http"

    async def handle_session(
        self,
        session: HoneypotSession,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        # Keep-alive: scanners commonly pipeline a whole path list down one
        # socket, and each request is a separate observation.
        for _ in range(50):
            request = await self._read_request(session, reader)
            if request is None:
                return

            if request.malformed:
                session.record(
                    EventType.ERROR,
                    severity=Severity.MEDIUM,
                    tags=["malformed-http"],
                    extra={"reason": request.malformed},
                )
                await self.send(writer, self._raw_response(400, "text/html", "<h1>Bad Request</h1>"))
                return

            keep_alive = self._handle_request(session, request, writer)
            status, ctype, body = http_response_for(request.path, self.persona, self.hostname)
            await self.send(writer, self._raw_response(status, ctype, body, keep_alive))

            if not keep_alive:
                return

    # ------------------------------------------------------------------ #
    # Parsing
    # ------------------------------------------------------------------ #

    async def _read_request(
        self, session: HoneypotSession, reader: asyncio.StreamReader
    ) -> Optional[ParsedRequest]:
        request = ParsedRequest()

        request_line = await self.read_line(session, reader)
        if request_line is None:
            return None
        if not request_line.strip():
            return None

        parts = request_line.split()
        if len(parts) != 3:
            request.malformed = f"bad request line: {request_line[:120]!r}"
            return request
        request.method, request.path, request.version = parts
        if len(request.method) > 16:
            request.malformed = "method too long"
            return request

        for _ in range(MAX_HEADERS):
            line = await self.read_line(session, reader)
            if line is None:
                break
            if line == "":
                break
            if ":" not in line:
                request.malformed = f"bad header: {line[:120]!r}"
                return request
            key, _, value = line.partition(":")
            request.headers[key.strip().lower()] = value.strip()

        declared = request.headers.get("content-length", "")
        if declared.isdigit():
            # Trust the header only as an upper bound we choose.
            to_read = min(int(declared), MAX_BODY_BYTES)
            if to_read:
                request.body = await self.read_bytes(session, reader, to_read)

        return request

    # ------------------------------------------------------------------ #
    # Classification and recording
    # ------------------------------------------------------------------ #

    def _handle_request(
        self, session: HoneypotSession, request: ParsedRequest, writer: asyncio.StreamWriter
    ) -> bool:
        body_text = request.body.decode("utf-8", "replace")
        # Decode once for matching so %2e%2e%2f traversal is not missed, but
        # keep the raw path for the record — the encoding is itself evidence.
        haystack = "\n".join(
            [unquote_plus(request.path), body_text, *(f"{k}: {v}" for k, v in request.headers.items())]
        )

        tags: list[str] = []
        severity = Severity.INFO
        for tag, tag_severity, pattern in ATTACK_PATTERNS:
            if pattern.search(haystack):
                tags.append(tag)
                if tag_severity.rank > severity.rank:
                    severity = tag_severity

        if request.method not in ("GET", "POST", "HEAD", "PUT", "OPTIONS", "DELETE", "PATCH"):
            tags.append("unusual-method")
            severity = max(severity, Severity.MEDIUM, key=lambda s: s.rank)

        username, password = _extract_credentials(request, body_text)
        if username or password:
            tags.append("web-login-attempt")
            session.record(
                EventType.AUTH_ATTEMPT,
                severity=Severity.MEDIUM,
                username=username,
                password=password,
                http_method=request.method,
                path=request.path,
                user_agent=request.headers.get("user-agent"),
                tags=["http-form-login"],
            )

        digest = None
        if request.body:
            digest = self.logger.save_payload(request.body)

        status, _, _ = http_response_for(request.path, self.persona, self.hostname)
        recorded = session.record(
            EventType.HTTP_REQUEST,
            severity=severity,
            http_method=request.method,
            path=request.path,
            user_agent=request.headers.get("user-agent"),
            status_code=status,
            headers=_safe_headers(request.headers),
            payload_sha256=digest,
            payload_size=len(request.body),
            tags=tags,
            extra={"http_version": request.version},
        )
        if not recorded:
            return False

        connection = request.headers.get("connection", "").lower()
        if request.version == "HTTP/1.0":
            return connection == "keep-alive"
        return connection != "close"

    def _raw_response(
        self, status: int, content_type: str, body: str, keep_alive: bool = False
    ) -> bytes:
        reason = {
            200: "OK", 400: "Bad Request", 403: "Forbidden",
            404: "Not Found", 500: "Internal Server Error",
        }.get(status, "OK")
        encoded = body.encode("utf-8", "replace")

        headers = [
            f"HTTP/1.1 {status} {reason}",
            f"Server: {self.persona.http_server}",
            f"Content-Type: {content_type}; charset=UTF-8",
            f"Content-Length: {len(encoded)}",
            f"Connection: {'keep-alive' if keep_alive else 'close'}",
        ]
        if self.persona.http_powered_by:
            headers.append(f"X-Powered-By: {self.persona.http_powered_by}")
        return ("\r\n".join(headers) + "\r\n\r\n").encode() + encoded


def _extract_credentials(request: ParsedRequest, body_text: str) -> tuple[Optional[str], Optional[str]]:
    """Pull username/password out of a form post or a Basic auth header."""
    username = password = None

    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        import base64

        try:
            decoded = base64.b64decode(auth[6:].strip(), validate=True).decode("utf-8", "replace")
            if ":" in decoded:
                username, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            pass

    if username is None and body_text and "=" in body_text:
        try:
            fields = parse_qs(body_text, keep_blank_values=True)
        except ValueError:
            fields = {}
        for key, values in fields.items():
            lowered = key.lower()
            if lowered in CREDENTIAL_FIELDS and values:
                if "pass" in lowered or lowered == "pwd":
                    password = values[0][:256]
                else:
                    username = values[0][:256]

    return (username[:256] if username else None, password[:256] if password else None)


def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
    """Truncate header values before storage.

    A single request can carry hundreds of kilobytes of headers; storing them
    verbatim would let one attacker dominate the database.
    """
    return {k[:64]: v[:1024] for k, v in list(headers.items())[:MAX_HEADERS]}


__all__ = ["HTTPService", "ATTACK_PATTERNS", "ParsedRequest"]
