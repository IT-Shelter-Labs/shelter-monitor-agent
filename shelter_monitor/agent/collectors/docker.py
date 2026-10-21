"""Tiny Docker Engine API client over the unix socket (no docker CLI / SDK needed)."""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import threading
import urllib.parse
from dataclasses import dataclass
from typing import Any


class DockerError(Exception):
    pass


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect(self._socket_path)
        except BaseException:
            sock.close()
            raise
        self.sock = sock


@dataclass
class Container:
    id: str
    name: str
    image: str
    state: str          # running, exited, restarting, paused, created, dead
    status: str         # human readable, e.g. "Up 3 hours (healthy)"
    created: int

    @property
    def health(self) -> str:
        m = re.search(r"\((healthy|unhealthy|health: starting)\)", self.status)
        return m.group(1) if m else ""


class DockerClient:
    # Use only the API range exercised by this client. Docker 29 removed 1.41.
    MIN_API = (1, 41)  # Docker 20.10
    MAX_API = (1, 44)  # Docker 25+, including Docker 29's minimum

    def __init__(self, socket_path: str = "/var/run/docker.sock", timeout: float = 15):
        self.socket_path = socket_path
        self.timeout = timeout
        self._api_version: str | None = None
        self._version_lock = threading.Lock()

    def available(self) -> bool:
        return os.path.exists(self.socket_path)

    def _request(self, method: str, path: str, timeout: float | None = None, raw: bool = False) -> Any:
        version = self._negotiate_version()
        return self._send(method, f"/{version}{path}", timeout, raw)

    def _negotiate_version(self) -> str:
        with self._version_lock:
            if self._api_version is not None:
                return self._api_version
            info = self._send("GET", "/version")
            if not isinstance(info, dict):
                raise DockerError("docker /version: invalid response")

            def parse(value: Any) -> tuple[int, int]:
                if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+", value):
                    raise DockerError("docker /version: invalid API version")
                major, minor = value.split(".")
                return int(major), int(minor)

            server_max = parse(info.get("ApiVersion"))
            server_min = parse(info.get("MinAPIVersion", "1.12"))
            selected = min(server_max, self.MAX_API)
            if selected < max(server_min, self.MIN_API):
                raise DockerError("docker API version range is incompatible with this agent (supported: 1.41-1.44)")
            self._api_version = f"v{selected[0]}.{selected[1]}"
            return self._api_version

    def _send(self, method: str, path: str, timeout: float | None = None, raw: bool = False) -> Any:
        conn = _UnixHTTPConnection(self.socket_path, timeout or self.timeout)
        try:
            conn.request(method, path, headers={"Host": "docker"})
            resp = conn.getresponse()
            body = resp.read()
        except (OSError, http.client.HTTPException) as exc:
            raise DockerError(f"docker socket error: {exc}") from None
        finally:
            conn.close()
        if resp.status >= 400:
            try:
                message = json.loads(body).get("message", "")
            except ValueError:
                message = body[:200].decode(errors="replace")
            raise DockerError(f"docker API {resp.status}: {message}")
        if raw:
            return body
        if not body:
            return None
        try:
            return json.loads(body)
        except ValueError:
            return body.decode(errors="replace")

    def ping(self) -> bool:
        try:
            self._send("GET", "/_ping")
            return True
        except DockerError:
            return False

    def version(self) -> dict[str, Any]:
        return self._send("GET", "/version")

    def containers(self) -> list[Container]:
        data = self._request("GET", "/containers/json?all=1")
        result = []
        for item in data or []:
            names = item.get("Names") or [""]
            result.append(
                Container(
                    id=item.get("Id", "")[:12],
                    name=names[0].lstrip("/"),
                    image=item.get("Image", ""),
                    state=item.get("State", ""),
                    status=item.get("Status", ""),
                    created=int(item.get("Created", 0)),
                )
            )
        return sorted(result, key=lambda c: c.name)

    def container(self, name: str) -> Container | None:
        for c in self.containers():
            if c.name == name or c.id == name:
                return c
        return None

    def networks(self) -> list[tuple[str, str]]:
        """(network name, IPv4 subnet) of all Docker networks."""
        result = []
        for net in self._request("GET", "/networks") or []:
            for cfg in (net.get("IPAM") or {}).get("Config") or []:
                subnet = cfg.get("Subnet", "")
                if subnet and ":" not in subnet:
                    result.append((net.get("Name", ""), subnet))
        return result

    def _post_container(self, name: str, action: str, timeout: int = 20) -> None:
        quoted = urllib.parse.quote(name, safe="")
        self._request("POST", f"/containers/{quoted}/{action}?t={int(timeout)}", timeout=timeout + 30)

    def restart(self, name: str, timeout: int = 20) -> None:
        self._post_container(name, "restart", timeout)

    def start(self, name: str) -> None:
        quoted = urllib.parse.quote(name, safe="")
        self._request("POST", f"/containers/{quoted}/start", timeout=60)

    def stop(self, name: str, timeout: int = 20) -> None:
        self._post_container(name, "stop", timeout)

    def logs(self, name: str, tail: int = 40) -> str:
        quoted = urllib.parse.quote(name, safe="")
        body = self._request("GET", f"/containers/{quoted}/logs?stdout=1&stderr=1&tail={int(tail)}", raw=True)
        return demux_logs(body or b"")

    def prune(self) -> tuple[int, int]:
        """Remove dangling images and build cache. Returns (images removed, bytes reclaimed)."""
        images = self._request("POST", "/images/prune", timeout=300) or {}
        reclaimed = int(images.get("SpaceReclaimed") or 0)
        removed = len(images.get("ImagesDeleted") or [])
        try:
            build = self._request("POST", "/build/prune", timeout=300) or {}
            reclaimed += int(build.get("SpaceReclaimed") or 0)
        except DockerError:
            pass  # old engines without the build cache API
        return removed, reclaimed


def demux_logs(body: bytes) -> str:
    """Docker multiplexes stdout/stderr of non-TTY containers with 8-byte frame headers."""
    out = bytearray()
    pos = 0
    framed = len(body) >= 8 and body[0] in (0, 1, 2) and body[1:4] == b"\x00\x00\x00"
    if not framed:
        return body.decode("utf-8", errors="replace")
    while pos + 8 <= len(body):
        size = int.from_bytes(body[pos + 4:pos + 8], "big")
        out += body[pos + 8:pos + 8 + size]
        pos += 8 + size
    return out.decode("utf-8", errors="replace")
