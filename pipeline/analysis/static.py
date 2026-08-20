"""Static analysis of captured payloads.

The sensor stores every uploaded artefact by SHA256 and never runs it. This
module is the other half of that arrangement: it says what a stored artefact
*is*, using nothing but the bytes.

    python -m pipeline.analysis.static --scan
    python -m pipeline.analysis.static data/payloads/<sha256>.bin

**The constraint that does not move:** nothing here executes a sample, and
nothing resolves or fetches a URL, domain or address found inside one. Every
indicator this module reports is defanged before it leaves the function, so a
URL cannot become a live link by being pasted into a ticket or a chat channel.

Why architecture is the headline field. IoT botnets ship one build of the same
dropper per CPU family and the loader picks by uname — so ``e_machine`` tells
you what the operator thought your device was. A honeypot advertising itself as
a generic Linux box that gets handed a MIPS binary has learned something the
session transcript alone does not say.

Everything degrades rather than fails. Truncated headers, hostile length
fields and files that are not what their magic bytes claim all produce a
partial result with ``errors`` populated, because a payload that crashes the
analyser is exactly the payload someone would send.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_PAYLOAD_DIR = PROJECT_ROOT / "data" / "payloads"

# Cap the work any single file can cause. A payload is attacker-chosen input.
MAX_STRINGS = 2000
MAX_STRING_LEN = 512
MAX_IOCS = 200

# --------------------------------------------------------------------------- #
# ELF / PE constants
# --------------------------------------------------------------------------- #

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"

# e_machine -> name. The IoT-relevant families are the point of this table;
# a dropper built for MIPS or ARM was not aimed at a server.
ELF_MACHINES = {
    0x02: "sparc",
    0x03: "x86",
    0x04: "m68k",
    0x08: "mips",
    0x14: "powerpc",
    0x15: "powerpc64",
    0x16: "s390",
    0x28: "arm",
    0x2A: "superh",
    0x32: "ia64",
    0x3E: "x86-64",
    0x5C: "arc",
    0xB7: "aarch64",
    0xF3: "riscv",
}
ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared-object", 4: "core"}
ELF_OSABI = {0: "sysv", 3: "linux", 9: "freebsd"}

PT_INTERP = 3
SHT_SYMTAB = 2

PE_MACHINES = {
    0x014C: "x86",
    0x0166: "mips",
    0x01C0: "arm",
    0x01C4: "armnt",
    0x0200: "ia64",
    0x8664: "x86-64",
    0xAA64: "aarch64",
}

# Other formats worth naming, longest magic first so a prefix cannot shadow a
# longer match.
MAGIC_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"\x7fELF", "elf", "application/x-executable"),
    (b"MZ", "pe", "application/vnd.microsoft.portable-executable"),
    # 0xCAFEBABE is also a Java class file; the ambiguity is inherent to the
    # magic, so the name says what was matched rather than guessing.
    (b"\xca\xfe\xba\xbe", "macho-fat-or-class", "application/x-mach-binary"),
    (b"\xcf\xfa\xed\xfe", "macho", "application/x-mach-binary"),
    (b"PK\x03\x04", "zip", "application/zip"),
    (b"\x1f\x8b", "gzip", "application/gzip"),
    (b"BZh", "bzip2", "application/x-bzip2"),
    (b"\xfd7zXZ", "xz", "application/x-xz"),
    (b"Rar!\x1a\x07", "rar", "application/vnd.rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "application/x-7z-compressed"),
    (b"\x89PNG", "png", "image/png"),
    (b"%PDF", "pdf", "application/pdf"),
)

# Strings that say what a dropper intends. Substring match on the extracted
# strings, lowercased. These are behavioural hints, not attribution.
INDICATIVE_STRINGS: tuple[tuple[str, str], ...] = (
    ("busybox", "iot:busybox"),
    ("/bin/busybox", "iot:busybox"),
    ("wget", "downloader:wget"),
    ("curl -", "downloader:curl"),
    ("tftp", "downloader:tftp"),
    ("chmod +x", "dropper:chmod"),
    ("chmod 777", "dropper:chmod"),
    ("/tmp/", "dropper:tmp-staging"),
    ("/dev/watchdog", "iot:watchdog-disable"),
    ("crontab", "persistence:cron"),
    ("/etc/rc.local", "persistence:rc-local"),
    ("authorized_keys", "persistence:ssh-key"),
    ("iptables", "defense-evasion:firewall"),
    ("/proc/self/exe", "anti-analysis:self-inspect"),
    ("ptrace", "anti-analysis:ptrace"),
    ("upx!", "packer:upx"),
    ("mirai", "family-string:mirai"),
    ("gafgyt", "family-string:gafgyt"),
    ("tsunami", "family-string:tsunami"),
    ("xmrig", "miner:xmrig"),
    ("stratum+tcp", "miner:stratum"),
    ("nc -e", "backdoor:netcat"),
    ("/dev/tcp/", "backdoor:bash-tcp"),
)

SHEBANG_INTERPRETERS = ("sh", "bash", "python", "perl", "ruby", "node", "php")

# --------------------------------------------------------------------------- #
# Indicator extraction
# --------------------------------------------------------------------------- #

URL_RE = re.compile(rb"""https?://[^\s"'<>\\)\x00]{4,2048}""", re.IGNORECASE)
IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(
    rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    rb"(?:com|net|org|ru|cn|info|biz|top|xyz|io|cc|su|tk|pw|onion)\b",
    re.IGNORECASE,
)


def defang(value: str) -> str:
    """Render a URL, domain or address inert: ``hxxp://evil[.]com/x``.

    Applied to every indicator this module returns. The point is that an
    analyst can paste the output anywhere — a ticket, a chat channel, a report
    — without a client turning it into a live link to a malware host.
    """
    return value.replace("http", "hxxp", 1).replace(".", "[.]")


def _valid_ipv4(raw: bytes) -> bool:
    try:
        parts = [int(p) for p in raw.split(b".")]
    except ValueError:
        return False
    return len(parts) == 4 and all(0 <= p <= 255 for p in parts)


def extract_iocs(data: bytes) -> dict[str, list[str]]:
    """URLs, IPv4 addresses and domains found in ``data``, all defanged."""
    urls: list[str] = []
    for match in URL_RE.findall(data)[:MAX_IOCS]:
        urls.append(defang(match.decode("utf-8", "replace")))

    addresses: list[str] = []
    for match in IPV4_RE.findall(data):
        if _valid_ipv4(match) and len(addresses) < MAX_IOCS:
            addresses.append(defang(match.decode("ascii", "replace")))

    domains: list[str] = []
    for match in DOMAIN_RE.findall(data)[:MAX_IOCS]:
        domains.append(defang(match.decode("utf-8", "replace").lower()))

    return {
        "urls": _dedupe(urls),
        "ipv4": _dedupe(addresses),
        "domains": _dedupe(domains),
    }


def _dedupe(values: list[str]) -> list[str]:
    """Order-preserving dedupe — first sighting wins."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


# --------------------------------------------------------------------------- #
# Strings and entropy
# --------------------------------------------------------------------------- #


def extract_strings(data: bytes, min_length: int = 6, utf16: bool = True) -> list[str]:
    """Printable ASCII runs, plus UTF-16LE runs (common in PE samples)."""
    pattern = rb"[\x20-\x7e]{%d,}" % max(1, min_length)
    found = [m.decode("ascii", "replace")[:MAX_STRING_LEN] for m in re.findall(pattern, data)]

    if utf16:
        wide = rb"(?:[\x20-\x7e]\x00){%d,}" % max(1, min_length)
        for match in re.findall(wide, data):
            found.append(match.decode("utf-16-le", "replace")[:MAX_STRING_LEN])

    return _dedupe(found)[:MAX_STRINGS]


def shannon_entropy(data: bytes) -> float:
    """Bits of entropy per byte, 0.0–8.0.

    Compressed and encrypted regions sit near 8.0; ordinary code and text sit
    well below. High entropy is a hint that a sample is packed, never proof —
    a zip file is not malware for being compressed.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def behaviour_tags(strings: list[str]) -> list[str]:
    """Behavioural hints from the strings table. Hints, not attribution."""
    haystack = "\n".join(strings).lower()
    return sorted({tag for needle, tag in INDICATIVE_STRINGS if needle in haystack})


# --------------------------------------------------------------------------- #
# Format parsers
# --------------------------------------------------------------------------- #


def identify(data: bytes) -> dict[str, str]:
    """File type from magic bytes. Never trusts a filename."""
    if not data:
        return {"file_type": "empty", "mime": "application/x-empty"}

    for magic, name, mime in MAGIC_SIGNATURES:
        if data.startswith(magic):
            return {"file_type": name, "mime": mime}

    if data.startswith(b"#!"):
        line = data[:128].split(b"\n", 1)[0].decode("ascii", "replace").lower()
        for interpreter in SHEBANG_INTERPRETERS:
            if interpreter in line:
                return {"file_type": f"script-{interpreter}", "mime": "text/x-shellscript"}
        return {"file_type": "script", "mime": "text/x-shellscript"}

    # No magic: call it text if it looks like text, otherwise raw bytes.
    sample = data[:1024]
    printable = sum(1 for b in sample if 0x20 <= b <= 0x7E or b in (9, 10, 13))
    if printable / len(sample) > 0.90:
        return {"file_type": "text", "mime": "text/plain"}
    return {"file_type": "unknown", "mime": "application/octet-stream"}


def parse_elf(data: bytes) -> dict[str, Any] | None:
    """ELF header details, or None if ``data`` is not an ELF.

    Bounds are checked against the actual buffer at every step: the offsets and
    counts being read are attacker-controlled, and a truncated sample must
    produce a partial answer rather than an exception.
    """
    if not data.startswith(ELF_MAGIC) or len(data) < 20:
        return None

    ei_class, ei_data, _, ei_osabi = data[4], data[5], data[6], data[7]
    is_64 = ei_class == 2
    endian = "<" if ei_data == 1 else ">"

    result: dict[str, Any] = {
        "bits": 64 if is_64 else 32 if ei_class == 1 else None,
        "endianness": "little" if ei_data == 1 else "big" if ei_data == 2 else None,
        "osabi": ELF_OSABI.get(ei_osabi, f"unknown({ei_osabi})"),
        "arch": None,
        "elf_type": None,
        "linkage": None,
        "stripped": None,
    }

    try:
        e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
    except struct.error:
        return result
    result["elf_type"] = ELF_TYPES.get(e_type, f"unknown({e_type})")
    result["arch"] = ELF_MACHINES.get(e_machine, f"unknown(0x{e_machine:x})")

    result["linkage"] = _elf_linkage(data, endian, is_64)
    result["stripped"] = _elf_stripped(data, endian, is_64)
    return result


def _elf_linkage(data: bytes, endian: str, is_64: bool) -> str | None:
    """ "static" or "dynamic", from the presence of a PT_INTERP segment.

    Statically linked and stripped is the shape of an IoT botnet dropper: it
    has to run on a device whose libc it cannot predict.
    """
    try:
        if is_64:
            (e_phoff,) = struct.unpack_from(endian + "Q", data, 32)
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 54)
        else:
            (e_phoff,) = struct.unpack_from(endian + "I", data, 28)
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 42)
    except struct.error:
        return None

    if not e_phoff or not e_phnum or e_phentsize < 4 or e_phnum > 4096:
        return None
    for i in range(e_phnum):
        offset = e_phoff + i * e_phentsize
        if offset + 4 > len(data):
            return None  # truncated: cannot say
        (p_type,) = struct.unpack_from(endian + "I", data, offset)
        if p_type == PT_INTERP:
            return "dynamic"
    return "static"


def _elf_stripped(data: bytes, endian: str, is_64: bool) -> bool | None:
    """True when no SHT_SYMTAB section is present."""
    try:
        if is_64:
            (e_shoff,) = struct.unpack_from(endian + "Q", data, 40)
            e_shentsize, e_shnum = struct.unpack_from(endian + "HH", data, 58)
        else:
            (e_shoff,) = struct.unpack_from(endian + "I", data, 32)
            e_shentsize, e_shnum = struct.unpack_from(endian + "HH", data, 46)
    except struct.error:
        return None

    if not e_shoff or not e_shnum or e_shentsize < 8 or e_shnum > 4096:
        return None
    for i in range(e_shnum):
        offset = e_shoff + i * e_shentsize
        if offset + 8 > len(data):
            return None
        (sh_type,) = struct.unpack_from(endian + "I", data, offset + 4)
        if sh_type == SHT_SYMTAB:
            return False
    return True


def parse_pe(data: bytes) -> dict[str, Any] | None:
    """PE/COFF header details, or None if ``data`` is not a PE."""
    if not data.startswith(PE_MAGIC) or len(data) < 0x40:
        return None

    result: dict[str, Any] = {"arch": None, "sections": None, "timestamp": None}
    try:
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    except struct.error:
        return result

    # An MZ stub with no PE header is a DOS executable, not a PE.
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return result

    try:
        machine, sections, timestamp = struct.unpack_from("<HHI", data, e_lfanew + 4)
    except struct.error:
        return result

    result["arch"] = PE_MACHINES.get(machine, f"unknown(0x{machine:x})")
    result["sections"] = sections
    result["timestamp"] = timestamp
    return result


def yara_scan(data: bytes, rules_dir: Path | None = None) -> list[str]:
    """Matching YARA rule names, or [] when yara-python is not installed.

    Optional on purpose, like ``geoip2`` elsewhere: the analyser must produce a
    useful answer on a machine that has no YARA and no rules.
    """
    try:
        import yara  # type: ignore[import-untyped]
    except ImportError:
        return []

    directory = rules_dir or (PROJECT_ROOT / "data" / "yara")
    if not directory.is_dir():
        return []

    sources = {p.stem: str(p) for p in sorted(directory.glob("*.yar"))}
    sources.update({p.stem: str(p) for p in sorted(directory.glob("*.yara"))})
    if not sources:
        return []
    try:
        compiled = yara.compile(filepaths=sources)
        return sorted({str(m) for m in compiled.match(data=data)})
    except Exception:  # pragma: no cover - malformed rules are the operator's
        return []


# --------------------------------------------------------------------------- #
# Top level
# --------------------------------------------------------------------------- #


def analyze(data: bytes, *, min_string_length: int = 6) -> dict[str, Any]:
    """Full static profile of one artefact. Never raises on hostile input."""
    errors: list[str] = []
    result: dict[str, Any] = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "entropy": round(shannon_entropy(data), 3),
        "arch": None,
        "linkage": None,
        "stripped": None,
        "format_details": {},
        "behaviour_tags": [],
        "yara_matches": [],
        "errors": errors,
    }
    result.update(identify(data))

    strings: list[str] = []
    try:
        strings = extract_strings(data, min_length=min_string_length)
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"strings: {type(exc).__name__}")
    result["strings_count"] = len(strings)
    result["strings"] = strings

    try:
        result["iocs"] = extract_iocs(data)
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"iocs: {type(exc).__name__}")
        result["iocs"] = {"urls": [], "ipv4": [], "domains": []}

    try:
        result["behaviour_tags"] = behaviour_tags(strings)
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"behaviour: {type(exc).__name__}")

    try:
        if result["file_type"] == "elf":
            details = parse_elf(data) or {}
            result["format_details"] = details
            result["arch"] = details.get("arch")
            result["linkage"] = details.get("linkage")
            result["stripped"] = details.get("stripped")
        elif result["file_type"] == "pe":
            details = parse_pe(data) or {}
            result["format_details"] = details
            result["arch"] = details.get("arch")
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"header: {type(exc).__name__}")

    result["yara_matches"] = yara_scan(data)
    # High entropy in an already-compressed container says nothing.
    result["likely_packed"] = bool(
        result["entropy"] >= 7.2 and result["file_type"] in ("elf", "pe", "unknown")
    )
    return result


def analyze_file(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    """Analyse a file on disk. The file is read, never executed."""
    path = Path(path)
    data = path.read_bytes()
    result = analyze(data, **kwargs)
    result["filename"] = path.name
    return result


def scan_directory(directory: str | Path | None = None, **kwargs: Any) -> list[dict[str, Any]]:
    """Analyse every artefact in the payload store, newest first."""
    directory = Path(directory or DEFAULT_PAYLOAD_DIR)
    if not directory.is_dir():
        return []
    results: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.bin"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            results.append(analyze_file(path, **kwargs))
        except OSError as exc:
            results.append({"filename": path.name, "errors": [f"read: {exc}"]})
    return results


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _summarise(result: dict[str, Any]) -> str:
    bits = [
        result.get("filename") or result.get("sha256", "")[:12],
        result.get("file_type", "?"),
        f"{result.get('size', 0):,}B",
        f"H={result.get('entropy', 0)}",
    ]
    if result.get("arch"):
        bits.append(result["arch"])
    if result.get("linkage"):
        bits.append(result["linkage"])
    if result.get("stripped"):
        bits.append("stripped")
    if result.get("likely_packed"):
        bits.append("likely-packed")
    line = "  ".join(str(b) for b in bits)
    if result.get("behaviour_tags"):
        line += "\n    tags: " + ", ".join(result["behaviour_tags"])
    iocs = result.get("iocs") or {}
    for kind in ("urls", "domains", "ipv4"):
        if iocs.get(kind):
            line += f"\n    {kind}: " + ", ".join(iocs[kind][:5])
    return line


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    parser = argparse.ArgumentParser(
        description="Statically analyse captured payloads. Never executes a sample."
    )
    parser.add_argument("files", nargs="*", help="files to analyse")
    parser.add_argument(
        "--scan", action="store_true", help=f"analyse everything in {DEFAULT_PAYLOAD_DIR}"
    )
    parser.add_argument("--dir", help="payload directory for --scan")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a summary")
    parser.add_argument("--strings", action="store_true", help="include the strings table in JSON")
    parser.add_argument("--min-string", type=int, default=6, help="minimum string length")
    args = parser.parse_args(argv)

    if not args.files and not args.scan:
        parser.error("give one or more files, or --scan")

    results: list[dict[str, Any]] = []
    if args.scan:
        results += scan_directory(args.dir, min_string_length=args.min_string)
    for name in args.files:
        try:
            results.append(analyze_file(name, min_string_length=args.min_string))
        except OSError as exc:
            print(f"{name}: {exc}", file=sys.stderr)

    if not results:
        print("no payloads to analyse", file=sys.stderr)
        return 0

    if args.json:
        if not args.strings:
            for result in results:
                result.pop("strings", None)
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            print(_summarise(result))

    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = [
    "analyze",
    "analyze_file",
    "scan_directory",
    "identify",
    "parse_elf",
    "parse_pe",
    "extract_strings",
    "extract_iocs",
    "shannon_entropy",
    "behaviour_tags",
    "yara_scan",
    "defang",
]
