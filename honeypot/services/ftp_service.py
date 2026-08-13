"""FTP emulator (RFC 959 control channel).

FTP still attracts steady traffic from credential sprayers and from bots hunting
anonymous-writable servers to use as malware staging. This emulator serves the
control channel only — it advertises passive mode but never opens a data
connection, so there is no path by which the sensor transfers a file for anyone.

That is a deliberate limit, not an omission. A honeypot that accepts uploads is
storing attacker-chosen bytes on your disk, and one that honours ``PORT`` will
happily connect outbound to any address the attacker names — the classic FTP
bounce, which turns the sensor into a port scanner on someone else's behalf.
``PORT`` is therefore logged as a high-severity event and refused.
"""

from __future__ import annotations

import asyncio
import random

from honeypot.services.base import BaseService
from honeypot.session import HoneypotSession
from storage.models import EventType, Severity

# Commands that are meaningful before authentication.
PREAUTH_COMMANDS = {"USER", "PASS", "QUIT", "SYST", "FEAT", "HELP", "NOOP", "AUTH", "OPTS"}

FAKE_LISTING = (
    "drwxr-xr-x    2 0        0            4096 Mar 14 09:12 backup\r\n"
    "-rw-r--r--    1 0        0          104857 Feb 02 17:44 catalog.csv\r\n"
    "drwxr-xr-x    2 0        0            4096 Jan 08 11:20 incoming\r\n"
    "-rw-r--r--    1 0        0            1204 Dec 19 08:03 readme.txt\r\n"
)


class FTPService(BaseService):
    name = "ftp"

    async def handle_session(
        self,
        session: HoneypotSession,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        rng = random.Random(session.session_id)
        await self.send(writer, f"{self.persona.ftp_banner}\r\n")

        username: str | None = None
        authenticated = False
        cwd = "/"

        while True:
            line = await self.read_line(session, reader)
            if line is None:
                return
            if not line.strip():
                continue

            parts = line.split(" ", 1)
            command = parts[0].upper()[:16]
            argument = parts[1].strip() if len(parts) > 1 else ""

            if not authenticated and command not in PREAUTH_COMMANDS:
                await self.send(writer, "530 Please login with USER and PASS.\r\n")
                session.record(
                    EventType.COMMAND,
                    severity=Severity.LOW,
                    command=line,
                    tags=["ftp-preauth-refused"],
                )
                continue

            response, should_close = await self._dispatch(
                session,
                command,
                argument,
                rng,
                state={"username": username, "authenticated": authenticated, "cwd": cwd},
            )

            # State transitions the dispatcher signalled back.
            if command == "USER":
                username = argument
            elif command == "PASS" and response.startswith("230"):
                authenticated = True
                session.authenticated = True
                session.username = username
            elif command == "CWD" and response.startswith("250"):
                cwd = argument if argument.startswith("/") else f"{cwd.rstrip('/')}/{argument}"

            await self.send(writer, response)
            if should_close:
                return

    async def _dispatch(
        self,
        session: HoneypotSession,
        command: str,
        argument: str,
        rng: random.Random,
        state: dict,
    ) -> tuple[str, bool]:
        """Return ``(response_line, close_connection)``."""

        if command == "USER":
            anonymous = argument.lower() in ("anonymous", "ftp")
            session.record(
                EventType.AUTH_ATTEMPT,
                severity=Severity.MEDIUM,
                username=argument,
                command=f"USER {argument}",
                tags=["ftp-anonymous"] if anonymous else ["ftp-user"],
            )
            return f"331 Please specify the password for {argument}.\r\n", False

        if command == "PASS":
            username = state["username"] or ""
            session.seen_credentials.add((username, argument))
            session.record(
                EventType.AUTH_ATTEMPT,
                severity=Severity.MEDIUM,
                username=username,
                password=argument,
                command="PASS ****",
                tags=["ftp-password"],
            )
            # Anonymous is accepted more often than a named account, matching
            # how misconfigured real servers behave.
            anonymous = username.lower() in ("anonymous", "ftp")
            threshold = 0.8 if anonymous else self.settings.accept_login_rate
            if rng.random() < threshold:
                session.record(
                    EventType.AUTH_SUCCESS,
                    severity=Severity.HIGH,
                    username=username,
                    tags=["ftp-login-accepted"],
                )
                return "230 Login successful.\r\n", False
            await asyncio.sleep(rng.uniform(0.3, 1.0))
            return "530 Login incorrect.\r\n", False

        if command == "SYST":
            return "215 UNIX Type: L8\r\n", False

        if command == "FEAT":
            return (
                "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n"
                " SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n"
            ), False

        if command in ("PWD", "XPWD"):
            return f'257 "{state["cwd"]}" is the current directory\r\n', False

        if command == "CWD":
            session.record(
                EventType.COMMAND,
                severity=Severity.LOW,
                command=f"CWD {argument}",
                path=argument,
                tags=["ftp-navigate"],
            )
            return "250 Directory successfully changed.\r\n", False

        if command == "TYPE":
            return "200 Switching to Binary mode.\r\n", False

        if command == "PASV":
            # Advertised but never serviced; see the module docstring.
            session.record(
                EventType.COMMAND, severity=Severity.LOW, command="PASV", tags=["ftp-passive"]
            )
            return "227 Entering Passive Mode (127,0,0,1,39,17).\r\n", False

        if command == "PORT":
            # Active mode would have us dial out to an attacker-chosen address.
            session.record(
                EventType.COMMAND,
                severity=Severity.HIGH,
                command=f"PORT {argument}",
                tags=["ftp-bounce-attempt"],
                extra={"refused": "active-mode data connections are never opened"},
            )
            return "500 Illegal PORT command.\r\n", False

        if command in ("LIST", "NLST"):
            session.record(
                EventType.COMMAND,
                severity=Severity.LOW,
                command=line_for(command, argument),
                tags=["ftp-list"],
            )
            return "150 Here comes the directory listing.\r\n226 Directory send OK.\r\n", False

        if command in ("STOR", "STOU", "APPE"):
            session.record(
                EventType.FILE_UPLOAD,
                severity=Severity.CRITICAL,
                command=line_for(command, argument),
                path=argument,
                tags=["ftp-upload-attempt"],
                extra={"refused": "no data channel is ever opened"},
            )
            return "550 Permission denied.\r\n", False

        if command == "RETR":
            session.record(
                EventType.COMMAND,
                severity=Severity.MEDIUM,
                command=line_for(command, argument),
                path=argument,
                tags=["ftp-download-attempt"],
            )
            return "550 Failed to open file.\r\n", False

        if command in ("DELE", "RMD", "MKD", "RNFR", "RNTO", "SITE"):
            session.record(
                EventType.COMMAND,
                severity=Severity.HIGH,
                command=line_for(command, argument),
                path=argument,
                tags=["ftp-modify-attempt"],
            )
            return "550 Permission denied.\r\n", False

        if command == "QUIT":
            return "221 Goodbye.\r\n", True

        if command == "NOOP":
            return "200 NOOP ok.\r\n", False

        session.record(
            EventType.COMMAND,
            severity=Severity.LOW,
            command=line_for(command, argument),
            tags=["ftp-unknown"],
        )
        return "500 Unknown command.\r\n", False


def line_for(command: str, argument: str) -> str:
    return f"{command} {argument}".strip()


__all__ = ["FTPService"]
