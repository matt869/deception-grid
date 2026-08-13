"""Service banners and host personas.

A honeypot is only as good as its consistency. If the SSH banner claims Debian
12 while the HTTP ``Server`` header says CentOS and ``uname -a`` reports
FreeBSD, any attacker paying attention leaves immediately — and the ones worth
studying are exactly the ones paying attention.

So personas are defined as a single object per host archetype, and every
service pulls its banner, prompts and command output from the same one. Adding
a persona means adding one entry here, not editing four services.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Persona:
    """A coherent fake host identity shared across every emulated service."""

    key: str
    description: str

    # -- OS identity --------------------------------------------------------
    os_name: str
    kernel: str
    arch: str
    distro_pretty: str

    # -- per-service banners ------------------------------------------------
    ssh_version: str  # the SSH-2.0-... protocol string
    telnet_greeting: str
    ftp_banner: str
    http_server: str
    http_powered_by: str = ""

    # -- shell --------------------------------------------------------------
    motd: str = ""
    shell_user: str = "root"
    shell_prompt_root: str = "{user}@{host}:{cwd}# "
    shell_prompt_user: str = "{user}@{host}:{cwd}$ "

    # -- files that `ls`, `cat` etc. will find -----------------------------
    fake_users: tuple[str, ...] = ("root", "ubuntu", "admin", "www-data")
    fake_packages: tuple[str, ...] = field(default=())

    def prompt(self, user: str, host: str, cwd: str) -> str:
        template = self.shell_prompt_root if user == "root" else self.shell_prompt_user
        display_cwd = "~" if cwd in (f"/home/{user}", "/root") else cwd
        return template.format(user=user, host=host, cwd=display_cwd)


PERSONAS: dict[str, Persona] = {
    "ubuntu-generic": Persona(
        key="ubuntu-generic",
        description="Stock Ubuntu 22.04 LTS cloud image — the most-scanned target on the internet",
        os_name="Ubuntu 22.04.3 LTS",
        kernel="5.15.0-91-generic",
        arch="x86_64",
        distro_pretty="Ubuntu 22.04.3 LTS",
        ssh_version="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5",
        telnet_greeting="Ubuntu 22.04.3 LTS",
        ftp_banner="220 (vsFTPd 3.0.5)",
        http_server="Apache/2.4.52 (Ubuntu)",
        motd=(
            "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n"
            "\n"
            " * Documentation:  https://help.ubuntu.com\n"
            " * Management:     https://landscape.canonical.com\n"
            " * Support:        https://ubuntu.com/advantage\n"
            "\n"
            "  System information as of {date}\n"
            "\n"
            "  System load:  0.08              Processes:             112\n"
            "  Usage of /:   41.2% of 38.6GB   Users logged in:       0\n"
            "  Memory usage: 27%               IPv4 address for eth0: {ip}\n"
            "  Swap usage:   0%\n"
            "\n"
            "Last login: {last_login} from {last_ip}\n"
        ),
        fake_users=("root", "ubuntu", "www-data", "postgres", "deploy"),
        fake_packages=("openssh-server", "apache2", "postgresql-14", "python3.10", "curl"),
    ),
    "centos-legacy": Persona(
        key="centos-legacy",
        description="End-of-life CentOS 7 box — bait for exploit kits targeting unpatched RHEL derivatives",
        os_name="CentOS Linux 7 (Core)",
        kernel="3.10.0-1160.el7.x86_64",
        arch="x86_64",
        distro_pretty="CentOS Linux release 7.9.2009 (Core)",
        ssh_version="SSH-2.0-OpenSSH_7.4",
        telnet_greeting="CentOS Linux 7 (Core)",
        ftp_banner="220 (vsFTPd 3.0.2)",
        http_server="Apache/2.4.6 (CentOS)",
        http_powered_by="PHP/5.4.16",
        motd="Last login: {last_login} from {last_ip}\n",
        fake_users=("root", "centos", "apache", "mysql", "oracle"),
        fake_packages=("openssh-7.4p1", "httpd-2.4.6", "php-5.4.16", "mysql-5.5.68"),
    ),
    "iot-router": Persona(
        key="iot-router",
        description="Consumer router with BusyBox — the archetype Mirai-class botnets hunt over telnet",
        os_name="Linux",
        kernel="2.6.36",
        arch="mips",
        distro_pretty="BusyBox v1.19.4 (2016-03-14) built-in shell (ash)",
        ssh_version="SSH-2.0-dropbear_2012.55",
        telnet_greeting="\r\nMediaAccess TG789vac\r\n",
        ftp_banner="220 Welcome to the FTP service",
        http_server="lighttpd/1.4.32",
        motd=(
            "BusyBox v1.19.4 (2016-03-14 10:22:41 CST) built-in shell (ash)\n"
            "Enter 'help' for a list of built-in commands.\n\n"
        ),
        shell_user="root",
        shell_prompt_root="# ",
        shell_prompt_user="$ ",
        fake_users=("root", "admin", "support", "user"),
        fake_packages=(),
    ),
    "windows-iis": Persona(
        key="windows-iis",
        description="Windows Server 2016 running IIS — catches SMB/RDP-adjacent web scanning",
        os_name="Microsoft Windows Server 2016 Standard",
        kernel="10.0.14393",
        arch="AMD64",
        distro_pretty="Microsoft Windows [Version 10.0.14393.6351]",
        ssh_version="SSH-2.0-OpenSSH_for_Windows_8.1",
        telnet_greeting="Microsoft Telnet Service",
        ftp_banner="220 Microsoft FTP Service",
        http_server="Microsoft-IIS/10.0",
        http_powered_by="ASP.NET",
        motd="Microsoft Windows [Version 10.0.14393.6351]\n(c) 2016 Microsoft Corporation. All rights reserved.\n\n",
        shell_user="Administrator",
        shell_prompt_root="C:\\{cwd}>",
        shell_prompt_user="C:\\{cwd}>",
        fake_users=("Administrator", "Guest", "svc_backup", "iisuser"),
        fake_packages=(),
    ),
}

DEFAULT_PERSONA = "ubuntu-generic"


def get_persona(key: str | None = None) -> Persona:
    """Look up a persona, falling back to the default rather than raising.

    A typo in ``HONEYPOT_PERSONA`` should degrade to a working sensor, not a
    crashed one — a honeypot that fails to start collects nothing.
    """
    if not key:
        return PERSONAS[DEFAULT_PERSONA]
    return PERSONAS.get(key, PERSONAS[DEFAULT_PERSONA])


def list_personas() -> list[dict[str, str]]:
    return [{"key": p.key, "description": p.description} for p in PERSONAS.values()]


# --------------------------------------------------------------------------- #
# Small helpers used by the services to make banners feel lived-in
# --------------------------------------------------------------------------- #

_FAKE_LAST_IPS = (
    "10.0.4.17",
    "192.168.1.42",
    "172.16.8.9",
    "10.20.30.11",
    "192.168.0.104",
)


def fake_last_login_ip(rng: random.Random | None = None) -> str:
    """An RFC1918 address, so the persona looks like it has real admins.

    Private ranges only: a plausible-looking public IP in a banner is somebody
    else's address, and inventing traffic from it is not ours to do.
    """
    return (rng or random).choice(_FAKE_LAST_IPS)


__all__ = [
    "Persona",
    "PERSONAS",
    "DEFAULT_PERSONA",
    "get_persona",
    "list_personas",
    "fake_last_login_ip",
]
