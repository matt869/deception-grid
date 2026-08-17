"""Unit tests for the Docker Engine API emulator.

Tests the classify-and-score path against the request bodies real attackers send
at an exposed daemon. No sockets: the goal is to pin down that a host-mount
create call is scored as the host takeover it is, and never as ordinary traffic.
"""

from __future__ import annotations

import json

import pytest

from honeypot.services.docker_service import DANGEROUS_BINDS, DockerService, _privileged
from storage.models import Severity


@pytest.fixture
def service():
    # The classify/assess/respond paths never touch settings or sockets, so an
    # uninitialised instance is enough and keeps the test free of fixtures.
    return DockerService.__new__(DockerService)


def _create_body(**host_config) -> bytes:
    payload = {
        "Image": host_config.pop("image", "alpine:latest"),
        "Cmd": host_config.pop("cmd", ["/bin/sh"]),
        "HostConfig": host_config,
    }
    return json.dumps(payload).encode()


class TestRouteClassification:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/_ping", "ping"),
            ("/version", "version"),
            ("/v1.43/version", "version"),
            ("/info", "info"),
            ("/containers/json", "containers-list"),
            ("/v1.24/containers/json?all=1", "containers-list"),
            ("/containers/create", "containers-create"),
            ("/v1.43/containers/create?name=x", "containers-create"),
            ("/containers/abc123/start", "containers-start"),
            ("/containers/abc123/exec", "containers-exec"),
            ("/exec/deadbeef/start", "exec-start"),
            ("/images/create?fromImage=alpine", "images-create"),
            ("/images/json", "images-list"),
            ("/nope", "other"),
        ],
    )
    def test_classifies(self, service, path, expected):
        assert service._classify(path) == expected


class TestSeverity:
    def test_recon_is_medium_never_ignored(self, service):
        """An exposed daemon being enumerated is never routine traffic."""
        tags, severity = service._assess("version", b"")
        assert severity == Severity.MEDIUM
        assert "docker-recon" in tags

    def test_plain_create_is_high(self, service):
        tags, severity = service._assess("containers-create", _create_body())
        assert severity == Severity.HIGH
        assert "docker-container-create" in tags
        assert "docker-host-mount" not in tags

    def test_root_bind_is_critical(self, service):
        tags, severity = service._assess("containers-create", _create_body(Binds=["/:/mnt"]))
        assert severity == Severity.CRITICAL
        assert "docker-host-mount" in tags
        assert "docker-host-takeover" in tags

    def test_docker_socket_bind_is_critical(self, service):
        body = _create_body(Binds=["/var/run/docker.sock:/var/run/docker.sock"])
        tags, severity = service._assess("containers-create", body)
        assert severity == Severity.CRITICAL
        assert "docker-host-mount" in tags

    def test_etc_bind_is_critical(self, service):
        tags, severity = service._assess("containers-create", _create_body(Binds=["/etc:/hostetc"]))
        assert severity == Severity.CRITICAL
        assert "docker-host-mount" in tags

    def test_privileged_is_critical(self, service):
        tags, severity = service._assess("containers-create", _create_body(Privileged=True))
        assert severity == Severity.CRITICAL
        assert "docker-privileged" in tags

    def test_miner_image_is_critical(self, service):
        body = _create_body(image="xmrig/xmrig:latest")
        tags, severity = service._assess("containers-create", body)
        assert severity == Severity.CRITICAL
        assert "docker-cryptominer" in tags

    def test_exec_is_critical(self, service):
        for route in ("containers-start", "containers-exec", "exec-start"):
            tags, severity = service._assess(route, b"")
            assert severity == Severity.CRITICAL, route
            assert "docker-execute" in tags

    def test_image_pull_is_high(self, service):
        _tags, severity = service._assess("images-create", b"")
        assert severity == Severity.HIGH

    def test_every_request_is_tagged_docker_api(self, service):
        for route in ("ping", "version", "containers-create", "other"):
            tags, _ = service._assess(route, b"")
            assert "docker-api" in tags


class TestBindDetection:
    @pytest.mark.parametrize(
        "bind",
        ['"/:/mnt"', '"/etc:/x"', '"/root:/r"', '"/var/run/docker.sock:/s"', '"/proc:/p"'],
    )
    def test_dangerous_binds_match(self, bind):
        assert DANGEROUS_BINDS.search(bind)

    @pytest.mark.parametrize("bind", ['"/data:/data"', '"/opt/app:/app"', '"myvolume:/data"'])
    def test_ordinary_binds_do_not_match(self, bind):
        assert not DANGEROUS_BINDS.search(bind)


class TestPrivilegedParsing:
    def test_detects_privileged_json(self):
        assert _privileged(json.dumps({"HostConfig": {"Privileged": True}}))

    def test_detects_host_pid(self):
        assert _privileged(json.dumps({"HostConfig": {"PidMode": "host"}}))

    def test_false_when_absent(self):
        assert not _privileged(json.dumps({"HostConfig": {}}))

    def test_malformed_json_still_flags_on_raw_text(self):
        """A truncated body must not silently downgrade the severity."""
        assert _privileged('{"HostConfig": {"Privileged": true')

    def test_empty_body_is_not_privileged(self):
        assert not _privileged("")


class TestResponses:
    def test_version_is_well_formed_http(self, service):
        raw = service._respond("version", "/version")
        head, _, body = raw.partition("\r\n\r\n")
        assert head.startswith("HTTP/1.1 200 OK")
        assert "Content-Type: application/json" in head
        assert json.loads(body)["ApiVersion"]

    def test_create_returns_201_with_container_id(self, service):
        raw = service._respond("containers-create", "/containers/create")
        head, _, body = raw.partition("\r\n\r\n")
        assert head.startswith("HTTP/1.1 201 Created")
        assert len(json.loads(body)["Id"]) == 64

    def test_start_returns_204_with_no_body(self, service):
        raw = service._respond("containers-start", "/containers/x/start")
        assert raw.startswith("HTTP/1.1 204 No Content")
        assert raw.endswith("\r\n\r\n")

    def test_container_list_is_empty(self, service):
        _head, _, body = service._respond("containers-list", "/containers/json").partition(
            "\r\n\r\n"
        )
        assert json.loads(body) == []

    def test_unknown_route_is_404(self, service):
        assert service._respond("other", "/nope").startswith("HTTP/1.1 404")

    def test_content_length_matches_body(self, service):
        for route in ("version", "info", "containers-create", "containers-list"):
            head, _, body = service._respond(route, "/x").partition("\r\n\r\n")
            declared = int(
                next(h for h in head.splitlines() if h.lower().startswith("content-length")).split(
                    ":"
                )[1]
            )
            assert declared == len(body.encode()), route
