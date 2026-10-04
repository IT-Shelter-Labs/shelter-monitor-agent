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
        self.restarted = []

    def restart(self, name, timeout=20):
        self.restarted.append(name)


class ActionsTest(unittest.TestCase):
    def setUp(self):
        cfg = make_config(actions={"services": ["nginx"], "containers": ["web"], "use_sudo": "always"})
        self.bus = EventBus(Storage(":memory:"), "h")
        self.sink = Collect()
        self.bus.subscribe(self.sink)
        self.docker = FakeDocker()
        self.m = ActionManager(cfg.actions, self.bus, self.docker)  # type: ignore[arg-type]

    def test_only_allowlisted(self):
        with self.assertRaises(ActionError):
            self.m.request("service", "sshd.service", 1)
        with self.assertRaises(ActionError):
            self.m.request("shell", "nginx.service", 1)
        with self.assertRaises(ActionError):
            self.m.target_by_index("service", 5)

    def test_confirm_requires_same_user_and_is_single_use(self):
        a = self.m.request("container", "web", 1)
        with self.assertRaises(ActionError):
            self.m.confirm(a.token, 2)
        a = self.m.request("container", "web", 1)
        _, result = self.m.confirm(a.token, 1)
        self.assertTrue(result.startswith("Готово"))
        self.assertEqual(self.docker.restarted, ["web"])
        with self.assertRaises(ActionError):
            self.m.confirm(a.token, 1)
        self.assertEqual(self.sink.events[-1].kind, "action_executed")
        self.assertEqual(self.sink.events[-1].data["user_id"], 1)

    def test_expiry_and_cancel(self):
        a = self.m.request("container", "web", 1)
        a.expires = time.time() - 1
        with self.assertRaises(ActionError):
            self.m.confirm(a.token, 1)
        b = self.m.request("container", "web", 1)
        self.assertIsNone(self.m.cancel(b.token, 2))
        self.assertIsNotNone(self.m.cancel(b.token, 1))
        with self.assertRaises(ActionError):
            self.m.confirm(b.token, 1)

    def test_cooldown(self):
        self.m.confirm(self.m.request("container", "web", 1).token, 1)
        with self.assertRaises(ActionError):
            self.m.confirm(self.m.request("container", "web", 1).token, 1)

    def test_service_restart_argv_no_shell(self):
        a = self.m.request("service", "nginx.service", 7)
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("subprocess.run", return_value=completed) as run:
            _, result = self.m.confirm(a.token, 7)
        argv = run.call_args.args[0]
        self.assertEqual(argv[1:], ["-n", self.m.systemctl, "restart", "nginx.service"])
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertTrue(result.startswith("Готово"))

    def test_failed_restart_reported(self):
        a = self.m.request("service", "nginx.service", 7)
        completed = mock.Mock(returncode=1, stdout="", stderr="sudo: a password is required")
        with mock.patch("subprocess.run", return_value=completed):
            _, result = self.m.confirm(a.token, 7)
        self.assertTrue(result.startswith("Ошибка"))
        self.assertEqual(self.sink.events[-1].severity, "critical")

    def test_disabled(self):
        m = ActionManager(make_config(actions={"services": ["nginx"]}).actions, self.bus, None, enabled=False)
        with self.assertRaises(ActionError):
            m.request("service", "nginx.service", 1)

    def test_sudoers(self):
        rules = self.m.sudoers_rules("shelter")
        self.assertIn(f"shelter ALL=(root) NOPASSWD: {self.m.systemctl} restart nginx.service", rules)


if __name__ == "__main__":
    unittest.main()
