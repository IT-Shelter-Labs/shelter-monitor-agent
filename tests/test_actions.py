import time
import unittest
from unittest import mock

from shelter_monitor.agent.actions import ActionError, ActionManager
from shelter_monitor.agent.events import EventBus
from shelter_monitor.agent.storage import Storage
from tests.helpers import make_config


class Collect:
    def __init__(self):
        self.events = []

    def handle(self, event):
        self.events.append(event)


class FakeDocker:
    def __init__(self):
        self.calls = []

    def restart(self, name, timeout=20):
        self.calls.append(("restart", name))

    def start(self, name):
        self.calls.append(("start", name))

    def stop(self, name, timeout=20):
        self.calls.append(("stop", name))

    def prune(self):
        self.calls.append(("prune", ""))
        return 3, 5 * 1024 ** 3


class ActionsTest(unittest.TestCase):
    def setUp(self):
        self.cfg = make_config(actions={"services": ["nginx"], "containers": ["web*"], "use_sudo": "always"},
                               services={"units": ["cron"]})
        self.bus = EventBus(Storage(":memory:"), "h")
        self.sink = Collect()
        self.bus.subscribe(self.sink)
        self.docker = FakeDocker()
        self.restarted = []
        self.m = ActionManager(self.cfg.actions, self.bus, self.docker,  # type: ignore[arg-type]
                               monitored_units=["cron.service"], restart_agent=lambda: self.restarted.append(1))
        self.m.own_container = ""

    def test_allowlists(self):
        self.assertEqual(self.m.services, ["nginx.service", "cron.service"])  # explicit + monitored
        with self.assertRaises(ActionError):
            self.m.request("sr", "sshd.service", 1)
        with self.assertRaises(ActionError):
            self.m.request("cr", "db", 1)  # does not match web*
        with self.assertRaises(ActionError):
            self.m.request("zz", "", 1)
        self.m.request("cr", "web-1", 1)
        self.m.request("sr", "cron.service", 1)

    def test_monitored_services_can_be_disabled(self):
        cfg = make_config(actions={"allow_monitored_services": False}, services={"units": ["cron"]})
        m = ActionManager(cfg.actions, self.bus, None, monitored_units=["cron.service"])
        self.assertEqual(m.services, [])

    def test_confirm_requires_same_user_and_is_single_use(self):
        a = self.m.request("cr", "web", 1)
        with self.assertRaises(ActionError):
            self.m.confirm(a.token, 2)
        a = self.m.request("cr", "web", 1)
        _, ok, _ = self.m.confirm(a.token, 1)
        self.assertTrue(ok)
        self.assertEqual(self.docker.calls, [("restart", "web")])
        with self.assertRaises(ActionError):
            self.m.confirm(a.token, 1)
        self.assertEqual(self.sink.events[-1].kind, "action_executed")
        self.assertEqual(self.sink.events[-1].data["user_id"], 1)

    def test_container_ops_and_prune(self):
        for op in ("cs", "ct"):
            self.m.confirm(self.m.request(op, "web", 1).token, 1)
        _, ok, out = self.m.confirm(self.m.request("dp", "", 1).token, 1)
        self.assertTrue(ok)
        self.assertIn("5.0 GiB", out)
        self.assertEqual([c[0] for c in self.docker.calls], ["start", "stop", "prune"])

    def test_stop_rules(self):
        cfg = make_config(actions={"container_stop": False})
        m = ActionManager(cfg.actions, self.bus, self.docker)  # type: ignore[arg-type]
        with self.assertRaises(ActionError):
            m.request("ct", "web", 1)
        self.m.own_container = "abc123" + "0" * 58
        with self.assertRaises(ActionError):
            self.m.request("ct", "abc123", 1)  # the agent's own container

    def test_agent_restart(self):
        with mock.patch("threading.Timer") as timer:
            _, ok, _ = self.m.confirm(self.m.request("ar", "", 5).token, 5)
        self.assertTrue(ok)
        timer.return_value.start.assert_called_once()

    def test_expiry_and_cancel(self):
        a = self.m.request("cr", "web", 1)
        a.expires = time.time() - 1
        with self.assertRaises(ActionError):
            self.m.confirm(a.token, 1)
        b = self.m.request("cr", "web", 1)
        self.assertIsNone(self.m.cancel(b.token, 2))
        self.assertIsNotNone(self.m.cancel(b.token, 1))
        with self.assertRaises(ActionError):
            self.m.confirm(b.token, 1)
        c = self.m.request("cr", "web", 1)
        self.assertFalse(self.m.cancel_expired(c.token))  # still valid
        c.expires = time.time()
        self.assertTrue(self.m.cancel_expired(c.token))
        self.assertFalse(self.m.cancel_expired(c.token))

    def test_cooldown(self):
        self.m.confirm(self.m.request("cr", "web", 1).token, 1)
        with self.assertRaises(ActionError):
            self.m.confirm(self.m.request("cr", "web", 1).token, 1)

    def test_service_restart_argv_no_shell(self):
        a = self.m.request("sr", "nginx.service", 7)
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("subprocess.run", return_value=completed) as run:
            _, ok, _ = self.m.confirm(a.token, 7)
        argv = run.call_args.args[0]
        self.assertEqual(argv[1:], ["-n", self.m.systemctl, "restart", "nginx.service"])
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertTrue(ok)

    def test_failed_restart_reported_with_hint(self):
        a = self.m.request("sr", "nginx.service", 7)
        completed = mock.Mock(returncode=1, stdout="", stderr="sudo: a password is required")
        with mock.patch("subprocess.run", return_value=completed):
            _, ok, out = self.m.confirm(a.token, 7)
        self.assertFalse(ok)
        self.assertIn("sudoers", out)
        self.assertEqual(self.sink.events[-1].severity, "critical")

    def test_disabled(self):
        m = ActionManager(make_config(actions={"services": ["nginx"]}).actions, self.bus, None, enabled=False)
        with self.assertRaises(ActionError):
            m.request("sr", "nginx.service", 1)

    def test_buttons(self):
        self.assertEqual(self.m.service_buttons("nginx.service"), [[("🔁 Перезапустить", "a:sr:nginx.service")]])
        self.assertEqual(self.m.service_buttons("other.service"), [])
        labels = [b[0] for b in self.m.container_buttons("web", "exited")[0]]
        self.assertEqual(labels, ["▶️ Запустить", "🔁 Перезапустить", "📋 Логи"])
        self.assertIsNone(self.m.callback("cr", "x" * 80))  # callback_data limit

    def test_sudoers(self):
        rules = self.m.sudoers_rules("shelter")
        self.assertIn(f"shelter ALL=(root) NOPASSWD: {self.m.systemctl} restart nginx.service", rules)
        self.assertIn("restart cron.service", rules)

    def test_container_pattern_validation(self):
        make_config(actions={"containers": ["*", "web-?", "db[12]"]})
        from shelter_monitor.agent.config import ConfigError

        with self.assertRaises(ConfigError):
            make_config(actions={"containers": ["$(id)"]})


if __name__ == "__main__":
    unittest.main()
