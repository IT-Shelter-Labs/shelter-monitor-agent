import time
import unittest

from shelter_monitor.agent.events import AlertTracker, Event, EventBus
from shelter_monitor.agent.monitors.resources import ResourceMonitor
from shelter_monitor.agent.notifier import NotificationSettings, Notifier
from shelter_monitor.agent.storage import Storage
from shelter_monitor.telegram import split_message
from tests.helpers import FakeOutbox, make_config


class Collect:
    def __init__(self):
        self.events = []

    def handle(self, event):
        self.events.append(event)


def ev(sev="warning", cat="system", **data):
    return Event(cat, sev, "test", f"t-{sev}", data=data)


class TrackerTest(unittest.TestCase):
    def setUp(self):
        self.storage = Storage(":memory:")
        self.bus = EventBus(self.storage, "h")
        self.sink = Collect()
        self.bus.subscribe(self.sink)
        self.tracker = AlertTracker(self.bus)

    def test_edges_only(self):
        resolve = lambda d: Event("system", "info", "resolved", "ok")  # noqa: E731
        for _ in range(3):
            self.tracker.check("k", True, lambda: ev("warning"), resolve)
        self.assertEqual(len(self.sink.events), 1)
        self.tracker.check("k", True, lambda: ev("critical"), resolve)  # escalation
        self.assertEqual([e.severity for e in self.sink.events], ["warning", "critical"])
        self.tracker.check("k", False, lambda: ev(), resolve)
        self.tracker.check("k", False, lambda: ev(), resolve)
        self.assertEqual([e.kind for e in self.sink.events], ["test", "test", "resolved"])
        self.assertEqual(self.tracker.active(), [])
        self.assertEqual(len(self.storage.recent_events(10)), 3)

    def test_resource_monitor_disk_alert(self):
        class FakeCollector:
            def cpu_times(self):
                return (0, 0)

            def cpu_count(self):
                return 2

            def load(self):
                return (0.1, 0.1, 0.1)

            def memory(self):
                from shelter_monitor.agent.collectors.system import MemoryUsage
                return MemoryUsage(100, 50, 0, 0)

            def disks(self, mounts, ignore):
                from shelter_monitor.agent.collectors.system import DiskUsage
                return [DiskUsage("/", "/dev/sda1", "ext4", 100, 96, 4)]

            def temperature(self):
                return None

        cfg = make_config()
        mon = ResourceMonitor(cfg.monitor, FakeCollector(), self.tracker)  # type: ignore[arg-type]
        mon.tick()
        mon.tick()
        disk_events = [e for e in self.sink.events if e.kind == "disk_full"]
        self.assertEqual(len(disk_events), 1)
        self.assertEqual(disk_events[0].severity, "critical")


class NotifierTest(unittest.TestCase):
    def setUp(self):
        self.storage = Storage(":memory:")
        self.outbox = FakeOutbox()
        self.settings = NotificationSettings(self.storage)
        self.notifier = Notifier(self.outbox, [1, 2], "host", self.settings, "warning")

    def test_min_severity_and_forced(self):
        self.notifier.handle(ev("info"))
        self.assertEqual(self.outbox.sent, [])
        self.notifier.handle(ev("info", notify=True))
        self.assertEqual(len(self.outbox.sent), 2)  # two chats
        self.assertTrue(self.outbox.sent[0][3])  # info is silent
        self.notifier.handle(ev("warning", notify=False))
        self.assertEqual(len(self.outbox.sent), 2)

    def test_mute(self):
        self.settings.mute(3600)
        self.assertTrue(self.settings.is_muted())
        self.notifier.handle(ev("warning"))
        self.assertEqual(self.outbox.sent, [])
        self.notifier.handle(ev("critical"))
        self.assertEqual(len(self.outbox.sent), 2)
        self.settings.unmute()
        self.assertFalse(self.settings.is_muted())

    def test_categories(self):
        self.assertFalse(self.settings.toggle_category("docker"))
        self.notifier.handle(ev("warning", cat="docker"))
        self.assertEqual(self.outbox.sent, [])
        self.notifier.handle(ev("critical", cat="docker"))
        self.assertEqual(len(self.outbox.sent), 2)
        self.assertTrue(self.settings.toggle_category("docker"))
        self.assertEqual(self.settings.disabled_categories, set())

    def test_mute_persisted(self):
        self.settings.mute(60)
        self.assertGreater(NotificationSettings(self.storage).mute_until, time.time())


class SplitTest(unittest.TestCase):
    def test_split(self):
        text = "\n".join("x" * 100 for _ in range(100))
        chunks = split_message(text, 1000)
        self.assertTrue(all(len(c) <= 1000 for c in chunks))
        self.assertEqual("".join(chunks), text)
        self.assertEqual(split_message("y" * 2500, 1000), ["y" * 1000, "y" * 1000, "y" * 500])


if __name__ == "__main__":
    unittest.main()
