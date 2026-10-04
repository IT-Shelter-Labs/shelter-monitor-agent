import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from shelter_monitor.agent.config import HeartbeatSection
from shelter_monitor.agent.heartbeat import HeartbeatSender
from shelter_monitor.watchdog import config as wd_config
from shelter_monitor.watchdog.server import Watchdog, WatchdogServer

AGENT_TOKEN = "a" * 64
STATUS_TOKEN = "s" * 40


def make_cfg(tmp, **watchdog):
    return wd_config.from_dict({
        "watchdog": {"listen": "127.0.0.1", "port": 0, "data_file": os.path.join(tmp, "state.json"),
                     "default_timeout": 60, "status_token": STATUS_TOKEN, **watchdog},
        "telegram": {"token": "1:x", "chat_ids": [5]},
        "agents": [{"id": "srv1", "name": "Server One", "token": AGENT_TOKEN}],
    })


class WatchdogConfigTest(unittest.TestCase):
    def test_validation(self):
        with self.assertRaises(wd_config.ConfigError) as ctx:
            wd_config.from_dict({"telegram": {"token": "x", "chat_ids": [1]},
                                 "agents": [{"id": "a", "token": "short"}, {"id": "a", "token": "short"}]})
        self.assertIn("24 characters", str(ctx.exception))
        self.assertIn("duplicate", str(ctx.exception))

    def test_example(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        raw = wd_config.load_toml(os.path.join(root, "config", "watchdog.example.toml"))
        raw["telegram"].update(token="1:x", chat_ids=[1])
        cfg = wd_config.from_dict(raw)
        self.assertEqual(cfg.agents[0].id, "home-server")


class WatchdogLogicTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sent = []
        self.cfg = make_cfg(self.tmp.name)
        self.wd = Watchdog(self.cfg, self.sent.append)

    def tearDown(self):
        self.tmp.cleanup()

    def test_down_and_recovery(self):
        agent = self.wd.authenticate(AGENT_TOKEN)
        self.assertIsNotNone(agent)
        self.assertIsNone(self.wd.authenticate("b" * 64))
        t0 = self.wd.started_at + 10
        self.wd.heartbeat(agent, {"metrics": {"cpu_percent": 5}}, "1.2.3.4", now=t0)
        self.wd.check(now=t0 + 30)
        self.assertEqual(self.sent, [])
        self.wd.check(now=t0 + 61)
        self.assertEqual(len(self.sent), 1)
        self.assertIn("не отвечает", self.sent[0])
        self.wd.check(now=t0 + 200)
        self.assertEqual(len(self.sent), 1)  # no repeats without remind_interval
        self.wd.heartbeat(agent, {}, "1.2.3.4", now=t0 + 300)
        self.assertIn("снова на связи", self.sent[-1])
        # state survives restart
        wd2 = Watchdog(self.cfg, self.sent.append)
        self.assertEqual(wd2.state["srv1"].last_seen, t0 + 300)

    def test_grace_after_restart_and_never_seen(self):
        start = self.wd.started_at
        self.wd.check(now=start + 30)
        self.assertEqual(self.sent, [])
        self.wd.check(now=start + 61)
        self.assertIn("ни разу", self.sent[0])
        self.wd.check(now=start + 120)
        self.assertEqual(len(self.sent), 1)


class WatchdogHTTPTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sent = []
        self.server = WatchdogServer(Watchdog(make_cfg(self.tmp.name), self.sent.append))
        self.port = self.server.httpd.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self.tmp.cleanup()

    def request(self, path, token=None, data=None, method=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_endpoints(self):
        self.assertEqual(self.request("/healthz"), (200, b"ok\n"))
        self.assertEqual(self.request("/api/v1/heartbeat", "wrong", b"{}")[0], 401)
        self.assertEqual(self.request("/api/v1/heartbeat", AGENT_TOKEN, b"[1]")[0], 400)
        self.assertEqual(self.request("/api/v1/heartbeat", AGENT_TOKEN, b"x" * 70000)[0], 413)
        self.assertEqual(self.request("/api/v1/status")[0], 401)
        self.assertEqual(self.request("/nope")[0], 404)

    def test_agent_sender_end_to_end(self):
        for method in ("POST", "GET"):
            sender = HeartbeatSender(
                HeartbeatSection(enabled=True, url=self.base + "/api/v1/heartbeat", token=AGENT_TOKEN, method=method),
                "srv1", "boot-1", lambda: {"cpu_percent": 12.5}, lambda: 0)
            sender.tick()
            self.assertGreater(sender.last_ok, 0, sender.last_error)
        status, body = self.request("/api/v1/status", STATUS_TOKEN)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["agents"][0]["online"])
        self.assertEqual(data["agents"][0]["metrics"]["cpu_percent"], 12.5)

    def test_sender_records_failure(self):
        sender = HeartbeatSender(
            HeartbeatSection(enabled=True, url=self.base + "/api/v1/heartbeat", token="bad", method="POST"),
            "srv1", "", lambda: {}, lambda: 0)
        sender.tick()
        self.assertEqual(sender.last_ok, 0)
        self.assertIn("Unauthorized", sender.last_error)


if __name__ == "__main__":
    unittest.main()
