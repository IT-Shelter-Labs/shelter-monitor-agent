"""Shelter Watchdog: receives agent heartbeats and alerts when a server goes silent.

Runs on a *different* machine than the monitored servers (a cheap VPS, a Raspberry Pi
at another location...). It is intentionally tiny and is the seed of the future
Shelter Monitor Hub: the heartbeat payload already carries agent identity and a
metrics summary.

HTTP API:
  POST|GET /api/v1/heartbeat   Authorization: Bearer <agent token>   -> 204
  GET      /api/v1/status      Authorization: Bearer <status_token>  -> JSON
  GET      /healthz                                                  -> 200 ok
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from shelter_monitor import __version__
from shelter_monitor.util import esc, fmt_duration, fmt_ts
from shelter_monitor.watchdog.config import AgentEntry, WatchdogConfig

log = logging.getLogger(__name__)

MAX_BODY = 64 * 1024


@dataclass
class AgentState:
    id: str
    last_seen: float = 0.0
    last_addr: str = ""
    down: bool = False
    down_since: float = 0.0
    last_reminder: float = 0.0
    never_seen_alerted: bool = False
    boot_id: str = ""
    payload: dict[str, Any] = field(default_factory=dict)


class Watchdog:
    def __init__(self, cfg: WatchdogConfig, notify: Any):
        self.cfg = cfg
        self._notify = notify  # callable(text)
        self._lock = threading.Lock()
        self.started_at = time.time()
        self.agents: dict[str, AgentEntry] = {a.id: a for a in cfg.agents}
        self.state: dict[str, AgentState] = {a.id: AgentState(a.id) for a in cfg.agents}
        self._load_state()

    # -- persistence -------------------------------------------------------------------

    def _load_state(self) -> None:
        try:
            with open(self.cfg.data_file, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return
        for agent_id, raw in data.get("agents", {}).items():
            if agent_id in self.state and isinstance(raw, dict):
                known = {k: v for k, v in raw.items() if k in AgentState.__dataclass_fields__}
                self.state[agent_id] = AgentState(**{**known, "id": agent_id})

    def save_state(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.cfg.data_file))
        os.makedirs(directory, exist_ok=True)
        tmp = self.cfg.data_file + ".tmp"
        with self._lock:
            data = {"version": 1, "agents": {k: asdict(v) for k, v in self.state.items()}}
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, self.cfg.data_file)

    # -- heartbeat handling ---------------------------------------------------------

    def authenticate(self, token: str) -> AgentEntry | None:
        found = None
        for agent in self.agents.values():  # compare against all tokens: constant time
            if hmac.compare_digest(agent.token.encode(), token.encode()):
                found = agent
        return found

    def heartbeat(self, agent: AgentEntry, payload: dict[str, Any], addr: str, now: float | None = None) -> None:
        now = now or time.time()
        with self._lock:
            st = self.state[agent.id]
            was_down, down_since = st.down, st.down_since
            st.last_seen = now
            st.last_addr = addr
            st.down = False
            st.down_since = 0.0
            st.never_seen_alerted = False
            if isinstance(payload.get("boot_id"), str):
                st.boot_id = payload["boot_id"]
            if payload:  # GET heartbeats carry no body: keep the last known data
                st.payload = {k: payload[k] for k in ("version", "hostname", "metrics", "active_alerts", "seq") if k in payload}
        if was_down:
            self._notify(f"✅ <b>{esc(agent.display)} снова на связи</b>\n"
                         f"Не было связи: {fmt_duration(now - down_since)}\nIP: <code>{esc(addr)}</code>")
            self.save_state()

    def check(self, now: float | None = None) -> None:
        now = now or time.time()
        changed = False
        for agent in self.agents.values():
            timeout = self.cfg.timeout_for(agent)
            with self._lock:
                st = self.state[agent.id]
                # After a watchdog restart give every agent a full timeout before judging it.
                reference = max(st.last_seen, self.started_at)
                silent_for = now - reference
                if st.last_seen == 0:
                    if silent_for > timeout and not st.never_seen_alerted:
                        st.never_seen_alerted = True
                        changed = True
                        message = (f"⚠️ <b>{esc(agent.display)}</b>: heartbeat ни разу не получен\n"
                                   f"Проверьте, что агент установлен и [heartbeat] настроен.")
                    else:
                        continue
                elif not st.down and silent_for > timeout:
                    st.down = True
                    st.down_since = st.last_seen
                    st.last_reminder = now
                    changed = True
                    metrics = st.payload.get("metrics") or {}
                    extra = ""
                    if metrics:
                        extra = (f"\nПоследние данные: CPU {metrics.get('cpu_percent', '?')}%, "
                                 f"RAM {metrics.get('mem_percent', '?')}%, диск {metrics.get('disk_max_percent', '?')}%")
                    message = (f"🚨 <b>{esc(agent.display)} не отвечает</b>\n"
                               f"Нет heartbeat уже {fmt_duration(now - st.last_seen)} "
                               f"(последний: {fmt_ts(st.last_seen)}).\n"
                               f"Возможно, сервер выключен, завис или пропала сеть.{extra}")
                elif st.down and self.cfg.remind_interval and now - st.last_reminder > self.cfg.remind_interval:
                    st.last_reminder = now
                    message = f"🚨 <b>{esc(agent.display)}</b> всё ещё недоступен ({fmt_duration(now - st.down_since)})"
                else:
                    continue
            self._notify(message)
        if changed:
            self.save_state()

    def status(self) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            agents = []
            for agent in self.agents.values():
                st = self.state[agent.id]
                agents.append({
                    "id": agent.id, "name": agent.display, "online": bool(st.last_seen) and not st.down,
                    "last_seen": st.last_seen or None, "seconds_since": round(now - st.last_seen) if st.last_seen else None,
                    "down_since": st.down_since or None, "addr": st.last_addr, **st.payload,
                })
        return {"version": __version__, "agents": agents}


def make_handler(wd: Watchdog) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "shelter-watchdog"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:  # route to logging, quieter
            log.debug("%s - %s", self.client_address[0], fmt % args)

        def _reply(self, code: int, body: bytes = b"", ctype: str = "text/plain; charset=utf-8") -> None:
            self.send_response(code)
            if body:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _token(self) -> str:
            auth = self.headers.get("Authorization", "")
            return auth[7:].strip() if auth.lower().startswith("bearer ") else ""

        def _client_ip(self) -> str:
            return self.client_address[0]

        def _heartbeat(self, payload: dict[str, Any]) -> None:
            agent = wd.authenticate(self._token())
            if agent is None:
                log.warning("heartbeat with invalid token from %s", self._client_ip())
                self._reply(401, b"unauthorized\n")
                return
            wd.heartbeat(agent, payload, self._client_ip())
            self._reply(204)

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                self._reply(200, b"ok\n")
            elif path == "/api/v1/heartbeat":
                self._heartbeat({})
            elif path == "/api/v1/status":
                token = self._token()
                if not wd.cfg.status_token or not hmac.compare_digest(token.encode(), wd.cfg.status_token.encode()):
                    self._reply(401, b"unauthorized\n")
                    return
                self._reply(200, json.dumps(wd.status(), ensure_ascii=False).encode(), "application/json")
            else:
                self._reply(404, b"not found\n")

        def do_POST(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] != "/api/v1/heartbeat":
                self._reply(404, b"not found\n")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                self._reply(413, b"payload too large\n")
                return
            raw = self.rfile.read(length) if length else b""
            try:
                payload = json.loads(raw) if raw else {}
                if not isinstance(payload, dict):
                    raise ValueError
            except ValueError:
                self._reply(400, b"invalid json\n")
                return
            self._heartbeat(payload)

    return Handler


class WatchdogServer:
    def __init__(self, wd: Watchdog):
        self.wd = wd
        self.httpd = ThreadingHTTPServer((wd.cfg.listen, wd.cfg.port), make_handler(wd))
        self.httpd.daemon_threads = True
        self.httpd.timeout = 10
        self._stop = threading.Event()
        self._checker = threading.Thread(target=self._check_loop, name="wd-check", daemon=True)

    def _check_loop(self) -> None:
        last_save = time.monotonic()
        while not self._stop.wait(self.wd.cfg.check_interval):
            try:
                self.wd.check()
                if time.monotonic() - last_save > 300:  # keep last_seen across crashes too
                    self.wd.save_state()
                    last_save = time.monotonic()
            except Exception:
                log.exception("check failed")

    def serve_forever(self) -> None:
        self._checker.start()
        log.info("shelter-watchdog %s listening on %s:%s, %d agent(s)", __version__, self.wd.cfg.listen,
                 self.wd.cfg.port, len(self.wd.agents))
        self.httpd.serve_forever(poll_interval=1)

    def request_stop(self) -> None:
        """Stop serving; safe to call from a signal handler thread."""
        self._stop.set()
        self.httpd.shutdown()

    def close(self) -> None:
        """Release the socket and persist state (call after serve_forever returned)."""
        self._stop.set()
        self.httpd.server_close()
        try:
            self.wd.save_state()
        except OSError:
            log.exception("failed to save state")

    def shutdown(self) -> None:
        self.request_stop()
        self.close()
