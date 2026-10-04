"""Tiny Docker Engine API client over the unix socket (no docker CLI / SDK needed)."""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
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
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
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
    API_VERSION = "v1.41"  # Docker 20.10+, still accepted by current engines

    def __init__(self, socket_path: str = "/var/run/docker.sock", timeout: float = 15):
        self.socket_path = socket_path
        self.timeout = timeout

    def available(self) -> bool:
        return os.path.exists(self.socket_path)

    def _request(self, method: str, path: str, timeout: float | None = None) -> Any:
        conn = _UnixHTTPConnection(self.socket_path, timeout or self.timeout)
        try:
            conn.request(method, f"/{self.API_VERSION}{path}", headers={"Host": "docker"})
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
        if not body:
            return None
        try:
            return json.loads(body)
        except ValueError:
            return body.decode(errors="replace")

    def ping(self) -> bool:
        try:
            self._request("GET", "/_ping")
            return True
        except DockerError:
            return False

    def version(self) -> dict[str, Any]:
        return self._request("GET", "/version")

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

    def restart(self, name: str, timeout: int = 20) -> None:
        quoted = urllib.parse.quote(name, safe="")
        self._request("POST", f"/containers/{quoted}/restart?t={int(timeout)}", timeout=timeout + 30)
