"""Fake command output and HTTP bodies.

This is the "medium interaction" layer: enough of a shell and a web server to
keep an automated attacker running its full playbook, so we capture the *whole*
sequence rather than just the login attempt.

Two rules govern everything here:

1. **Nothing executes.** Every response is a lookup or a formatted string. There
   is no subprocess call, no ``eval``, no filesystem write outside the payload
   directory. An emulator that can be tricked into running the attacker's input
   is not a honeypot, it is a compromised host.
2. **Nothing reaches out.** ``wget``/``curl`` record the requested URL and
   return a plausible transcript. The sensor never fetches attacker-supplied
   URLs — that would make it a proxy and a participant.
"""

from __future__ import annotations

import datetime as dt
import posixpath
import random
import re
from typing import Callable, Optional

from honeypot.deception.banners import Persona

# --------------------------------------------------------------------------- #
# A small fake filesystem
# --------------------------------------------------------------------------- #

FAKE_FS: dict[str, list[str]] = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "opt", "proc", "root",
          "run", "sbin", "srv", "sys", "tmp", "usr", "var"],
    "/root": [".bashrc", ".profile", ".ssh", "backup.tar.gz", "notes.txt"],
    "/root/.ssh": ["authorized_keys", "known_hosts"],
    "/home": ["ubuntu", "deploy"],
    "/home/ubuntu": [".bashrc", ".profile", ".ssh", "app"],
    "/tmp": [],
    "/var": ["backups", "cache", "lib", "log", "spool", "tmp", "www"],
    "/var/www": ["html"],
    "/var/www/html": ["index.html", "config.php", "uploads"],
    "/var/log": ["auth.log", "syslog", "apache2", "dpkg.log"],
    "/etc": ["passwd", "shadow", "hosts", "hostname", "resolv.conf", "ssh",
             "crontab", "os-release", "network", "apache2"],
}

FAKE_FILES: dict[str, str] = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        "deploy:x:1001:1001::/home/deploy:/bin/bash\n"
    ),
    # Deliberately unreadable — attempting to read it is itself the signal.
    "/etc/shadow": "cat: /etc/shadow: Permission denied",
    "/etc/hosts": "127.0.0.1\tlocalhost\n127.0.1.1\t{host}\n\n::1\tip6-localhost ip6-loopback\n",
    "/etc/hostname": "{host}\n",
    "/etc/resolv.conf": "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n",
    "/root/notes.txt": (
        "TODO:\n"
        "- rotate the deploy key before the audit\n"
        "- migrate cron jobs off this box\n"
        "- staging db creds are in the vault, not here\n"
    ),
    "/proc/version": "Linux version {kernel} (buildd@lcy02) (gcc 11.4.0) #1 SMP {date}\n",
    "/proc/cpuinfo": (
        "processor\t: 0\n"
        "vendor_id\t: GenuineIntel\n"
        "model name\t: Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz\n"
        "cpu MHz\t\t: 2300.000\n"
        "cache size\t: 46080 KB\n"
        "\n"
        "processor\t: 1\n"
        "vendor_id\t: GenuineIntel\n"
        "model name\t: Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz\n"
        "cpu MHz\t\t: 2300.000\n"
        "cache size\t: 46080 KB\n"
    ),
}


# --------------------------------------------------------------------------- #
# Shell emulation
# --------------------------------------------------------------------------- #


class FakeShell:
    """A stateful, non-executing shell emulator for one session."""

    def __init__(self, persona: Persona, hostname: str, username: str = "root") -> None:
        self.persona = persona
        self.hostname = hostname
        self.username = username
        self.cwd = "/root" if username == "root" else f"/home/{username}"
        self.env = {"HOME": self.cwd, "USER": username, "SHELL": "/bin/bash", "PWD": self.cwd}
        self.history: list[str] = []
        # URLs an attacker asked us to fetch. Never fetched — only recorded.
        self.download_attempts: list[str] = []

    @property
    def prompt(self) -> str:
        return self.persona.prompt(self.username, self.hostname, self.cwd)

    def run(self, line: str) -> str:
        """Return the fake stdout for ``line``. Never executes anything."""
        line = line.strip()
        if not line:
            return ""
        self.history.append(line)

        # Only the first command of a chain is emulated in detail; the rest are
        # acknowledged. Attack scripts routinely chain with ; && || and pipes,
        # and refusing them outright ends the session early.
        head = re.split(r"[;&|]{1,2}", line)[0].strip()
        parts = head.split()
        if not parts:
            return ""

        cmd = parts[0]
        args = parts[1:]

        # Strip common prefixes that wrap the real command.
        while cmd in {"sudo", "nohup", "time", "env"} and args:
            cmd, args = args[0], args[1:]

        handler = _HANDLERS.get(posixpath.basename(cmd))
        if handler is None:
            return f"-bash: {cmd}: command not found"
        return handler(self, args)

    # -- path helpers ---------------------------------------------------- #

    def resolve(self, path: str) -> str:
        if not path:
            return self.cwd
        if path == "~":
            return self.env["HOME"]
        if path.startswith("~/"):
            path = posixpath.join(self.env["HOME"], path[2:])
        if not path.startswith("/"):
            path = posixpath.join(self.cwd, path)
        return posixpath.normpath(path)

    def _render(self, text: str) -> str:
        return text.format(
            host=self.hostname,
            kernel=self.persona.kernel,
            date=dt.datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y"),
        )


# -- individual command handlers ----------------------------------------- #


def _cmd_ls(sh: FakeShell, args: list[str]) -> str:
    flags = [a for a in args if a.startswith("-")]
    targets = [a for a in args if not a.startswith("-")]
    path = sh.resolve(targets[0] if targets else "")

    entries = FAKE_FS.get(path)
    if entries is None:
        if path in FAKE_FILES:
            return posixpath.basename(path)
        return f"ls: cannot access '{targets[0] if targets else path}': No such file or directory"

    long_form = any("l" in f for f in flags)
    show_hidden = any("a" in f for f in flags)
    visible = entries if show_hidden else [e for e in entries if not e.startswith(".")]

    if not long_form:
        return "  ".join(visible)

    rng = random.Random(path)
    lines = [f"total {rng.randint(12, 96)}"]
    for name in visible:
        is_dir = posixpath.join(path, name) in FAKE_FS
        mode = "drwxr-xr-x" if is_dir else "-rw-r--r--"
        size = 4096 if is_dir else rng.randint(120, 48000)
        when = (dt.datetime.now() - dt.timedelta(days=rng.randint(1, 200))).strftime("%b %d %H:%M")
        lines.append(f"{mode} 1 root root {size:>8} {when} {name}")
    return "\n".join(lines)


def _cmd_cd(sh: FakeShell, args: list[str]) -> str:
    target = sh.resolve(args[0] if args else "~")
    if target in FAKE_FS:
        sh.cwd = target
        sh.env["PWD"] = target
        return ""
    return f"-bash: cd: {args[0] if args else '~'}: No such file or directory"


def _cmd_cat(sh: FakeShell, args: list[str]) -> str:
    if not args:
        return ""
    out = []
    for arg in args:
        path = sh.resolve(arg)
        if path in FAKE_FILES:
            out.append(sh._render(FAKE_FILES[path]).rstrip("\n"))
        elif path in FAKE_FS:
            out.append(f"cat: {arg}: Is a directory")
        else:
            out.append(f"cat: {arg}: No such file or directory")
    return "\n".join(out)


def _cmd_uname(sh: FakeShell, args: list[str]) -> str:
    p = sh.persona
    if any("a" in a for a in args if a.startswith("-")):
        stamp = dt.datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")
        return f"Linux {sh.hostname} {p.kernel} #1 SMP {stamp} {p.arch} {p.arch} {p.arch} GNU/Linux"
    if args and args[0] in ("-r",):
        return p.kernel
    if args and args[0] in ("-m",):
        return p.arch
    return "Linux"


def _cmd_whoami(sh: FakeShell, args: list[str]) -> str:
    return sh.username


def _cmd_id(sh: FakeShell, args: list[str]) -> str:
    if sh.username == "root":
        return "uid=0(root) gid=0(root) groups=0(root)"
    return (
        f"uid=1000({sh.username}) gid=1000({sh.username}) "
        f"groups=1000({sh.username}),27(sudo)"
    )


def _cmd_pwd(sh: FakeShell, args: list[str]) -> str:
    return sh.cwd


def _cmd_ps(sh: FakeShell, args: list[str]) -> str:
    return (
        "  PID TTY          TIME CMD\n"
        "    1 ?        00:00:04 systemd\n"
        "  412 ?        00:00:00 sshd\n"
        "  733 ?        00:00:01 apache2\n"
        "  918 ?        00:00:00 cron\n"
        " 1204 pts/0    00:00:00 bash\n"
        " 1291 pts/0    00:00:00 ps"
    )


def _cmd_free(sh: FakeShell, args: list[str]) -> str:
    return (
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:         3947416     1064212     1583920       12984     1299284     2612104\n"
        "Swap:              0           0           0"
    )


def _cmd_df(sh: FakeShell, args: list[str]) -> str:
    return (
        "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
        "/dev/root       40470732 16674988  23779360  42% /\n"
        "tmpfs            1973708        0   1973708   0% /dev/shm\n"
        "/dev/sda15        106858     6182    100676   6% /boot/efi"
    )


def _cmd_ifconfig(sh: FakeShell, args: list[str]) -> str:
    return (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 10.0.4.31  netmask 255.255.240.0  broadcast 10.0.15.255\n"
        "        ether 06:8a:1c:44:9e:02  txqueuelen 1000  (Ethernet)\n"
        "        RX packets 1842991  bytes 412889231 (412.8 MB)\n"
        "        TX packets 1633870  bytes 388120044 (388.1 MB)\n"
        "\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0\n"
        "        loop  txqueuelen 1000  (Local Loopback)"
    )


def _cmd_netstat(sh: FakeShell, args: list[str]) -> str:
    return (
        "Active Internet connections (only servers)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
        "tcp6       0      0 :::22                   :::*                    LISTEN"
    )


def _cmd_download(sh: FakeShell, args: list[str]) -> str:
    """Handle wget/curl.

    The URL is recorded as intelligence — second-stage payload locations are
    among the most valuable things a honeypot collects. It is never requested.
    """
    urls = [a for a in args if a.startswith(("http://", "https://", "ftp://"))]
    sh.download_attempts.extend(urls)
    if not urls:
        return "curl: try 'curl --help' for more information"
    url = urls[0]
    name = posixpath.basename(url.split("?")[0]) or "index.html"
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return (
        f"--{now}--  {url}\n"
        f"Resolving host... failed: Temporary failure in name resolution.\n"
        f"wget: unable to resolve host address\n"
        f"Cannot write to '{name}' (Network is unreachable)."
    )


def _cmd_echo(sh: FakeShell, args: list[str]) -> str:
    text = " ".join(args)
    return text.strip("'\"")


def _cmd_rm(sh: FakeShell, args: list[str]) -> str:
    return ""


def _cmd_history(sh: FakeShell, args: list[str]) -> str:
    return "\n".join(f"{i:>5}  {c}" for i, c in enumerate(sh.history, 1))


def _cmd_crontab(sh: FakeShell, args: list[str]) -> str:
    if args and args[0] == "-l":
        return "no crontab for " + sh.username
    return ""


def _cmd_w(sh: FakeShell, args: list[str]) -> str:
    now = dt.datetime.now().strftime("%H:%M:%S")
    return (
        f" {now} up 47 days,  3:12,  1 user,  load average: 0.08, 0.11, 0.09\n"
        "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        f"{sh.username:<8} pts/0    10.0.4.17        {now}    0.00s  0.02s  0.00s w"
    )


def _cmd_noop(sh: FakeShell, args: list[str]) -> str:
    return ""


def _cmd_exit(sh: FakeShell, args: list[str]) -> str:
    return "__EXIT__"


_HANDLERS: dict[str, Callable[[FakeShell, list[str]], str]] = {
    "ls": _cmd_ls, "dir": _cmd_ls,
    "cd": _cmd_cd,
    "cat": _cmd_cat, "head": _cmd_cat, "tail": _cmd_cat, "more": _cmd_cat, "less": _cmd_cat,
    "uname": _cmd_uname,
    "whoami": _cmd_whoami,
    "id": _cmd_id,
    "pwd": _cmd_pwd,
    "ps": _cmd_ps, "top": _cmd_ps,
    "free": _cmd_free,
    "df": _cmd_df,
    "ifconfig": _cmd_ifconfig, "ip": _cmd_ifconfig,
    "netstat": _cmd_netstat, "ss": _cmd_netstat,
    "wget": _cmd_download, "curl": _cmd_download, "tftp": _cmd_download,
    "echo": _cmd_echo,
    "rm": _cmd_rm, "mkdir": _cmd_noop, "touch": _cmd_noop, "chmod": _cmd_noop,
    "chown": _cmd_noop, "kill": _cmd_noop, "killall": _cmd_noop, "export": _cmd_noop,
    "history": _cmd_history,
    "crontab": _cmd_crontab,
    "w": _cmd_w, "who": _cmd_w, "last": _cmd_w,
    "exit": _cmd_exit, "logout": _cmd_exit, "quit": _cmd_exit,
}


# --------------------------------------------------------------------------- #
# HTTP responses
# --------------------------------------------------------------------------- #

LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{host} — Administration</title></head>
<body style="font-family:sans-serif;max-width:420px;margin:8rem auto">
  <h2>{host} administration</h2>
  <form method="post" action="/login">
    <p><label>Username<br><input name="username" autocomplete="username"></label></p>
    <p><label>Password<br><input name="password" type="password"></label></p>
    <p><button type="submit">Sign in</button></p>
  </form>
  <p style="color:#888;font-size:.85rem">Unauthorised access is prohibited and monitored.</p>
</body>
</html>
"""

INDEX_PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>It works!</title></head>
<body style="font-family:sans-serif;max-width:640px;margin:4rem auto">
  <h1>It works!</h1>
  <p>This is the default web page for this server.</p>
  <p>The web server software is running but no content has been added, yet.</p>
</body>
</html>
"""

NOT_FOUND_PAGE = """<!doctype html>
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL {path} was not found on this server.</p>
<hr><address>{server} Server at {host} Port 80</address></body></html>
"""

ROBOTS_TXT = "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /.git/\n"

# Paths that get a "juicy" response instead of a 404, because a scanner that
# finds something keeps going — and the follow-up requests are the interesting
# part. Every one of these is a decoy; none exposes real data.
BAIT_PATHS: dict[str, tuple[int, str, str]] = {
    "/": (200, "text/html", INDEX_PAGE),
    "/index.html": (200, "text/html", INDEX_PAGE),
    "/robots.txt": (200, "text/plain", ROBOTS_TXT),
    "/admin": (200, "text/html", LOGIN_PAGE),
    "/admin/": (200, "text/html", LOGIN_PAGE),
    "/login": (200, "text/html", LOGIN_PAGE),
    "/wp-login.php": (200, "text/html", LOGIN_PAGE),
    "/phpmyadmin/": (200, "text/html", LOGIN_PAGE),
    "/.env": (200, "text/plain",
              "APP_ENV=production\nAPP_DEBUG=false\nDB_HOST=127.0.0.1\n"
              "DB_DATABASE=app\nDB_USERNAME=app\nDB_PASSWORD=REDACTED\n"),
    "/.git/config": (200, "text/plain",
                     "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"
                     "\turl = git@internal.invalid:ops/site.git\n"),
    "/server-status": (403, "text/html",
                       "<html><head><title>403 Forbidden</title></head>"
                       "<body><h1>Forbidden</h1></body></html>"),
}


def http_response_for(path: str, persona: Persona, hostname: str) -> tuple[int, str, str]:
    """Return ``(status, content_type, body)`` for a requested path."""
    clean = path.split("?")[0]
    if clean in BAIT_PATHS:
        status, ctype, body = BAIT_PATHS[clean]
        return status, ctype, body.format(host=hostname, path=clean, server=persona.http_server)
    return (
        404,
        "text/html",
        NOT_FOUND_PAGE.format(path=clean, host=hostname, server=persona.http_server),
    )


__all__ = [
    "FakeShell",
    "FAKE_FS",
    "FAKE_FILES",
    "BAIT_PATHS",
    "http_response_for",
    "LOGIN_PAGE",
    "INDEX_PAGE",
]
