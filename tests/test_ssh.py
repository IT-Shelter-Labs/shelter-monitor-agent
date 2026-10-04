import json
import os
import tempfile
import threading
import time
import unittest

from shelter_monitor.agent.events import EventBus
from shelter_monitor.agent.ssh import (FileSource, SSHWatcher, parse_journal_entry, parse_message, parse_syslog_line,
                                       parse_syslog_timestamp)
from shelter_monitor.agent.storage import Storage
from tests.helpers import make_config


class Collect:
    def __init__(self):
        self.events = []

    def handle(self, event):
        self.events.append(event)


class ParserTest(unittest.TestCase):
    def test_accepted(self):
        a = parse_message("Accepted publickey for alice from 203.0.113.5 port 52814 ssh2: ED25519 SHA256:abc", 100.0)
        self.assertTrue(a.success)
        self.assertEqual((a.user, a.ip, a.method, a.port, a.ts), ("alice", "203.0.113.5", "publickey", 52814, 100.0))

    def test_failed_password(self):
        a = parse_message("Failed password for root from 198.51.100.7 port 4444 ssh2")
        self.assertFalse(a.success)
        self.assertEqual((a.user, a.ip, a.kind), ("root", "198.51.100.7", "failed"))

    def test_invalid_user_counted_once(self):
        a = parse_message("Invalid user admin from 198.51.100.7 port 4444")
        self.assertEqual((a.user, a.kind), ("admin", "invalid_user"))
        self.assertIsNone(parse_message("Failed password for invalid user admin from 198.51.100.7 port 4444 ssh2"))

    def test_preauth_and_max_attempts(self):
        a = parse_message("Connection closed by authenticating user root 198.51.100.9 port 5555 [preauth]")
        self.assertEqual((a.user, a.ip, a.kind), ("root", "198.51.100.9", "preauth_closed"))
        a = parse_message("error: maximum authentication attempts exceeded for invalid user test from 2001:db8::1 port 22 ssh2 [preauth]")
        self.assertEqual((a.user, a.ip), ("test", "2001:db8::1"))

    def test_irrelevant(self):
        self.assertIsNone(parse_message("Server listening on 0.0.0.0 port 22."))
        self.assertIsNone(parse_message("pam_unix(sshd:session): session opened for user alice"))

    def test_syslog_classic(self):
        line = "Oct  4 20:04:05 myhost sshd[1234]: Accepted password for bob from 192.168.1.20 port 50000 ssh2"
        a = parse_syslog_line(line)
        self.assertEqual(a.user, "bob")
        self.assertEqual(time.localtime(a.ts).tm_hour, 20)

    def test_syslog_rfc3339_and_sshd_session(self):
        line = ("2026-10-04T20:04:05.123456+00:00 myhost sshd-session[99]: "
                "Failed publickey for git from 10.0.0.1 port 1 ssh2")
        a = parse_syslog_line(line)
        self.assertEqual(a.user, "git")
        self.assertAlmostEqual(a.ts, 1791144245.123456, places=3)
        self.assertIsNone(parse_syslog_line("Oct  4 20:04:05 myhost CRON[1]: Accepted password for x from 1.1.1.1 port 1"))

    def test_year_rollover(self):
        import datetime as dt

        ts = parse_syslog_timestamp("Dec 31 23:59:59 h sshd[1]: x", now=dt.datetime(2027, 1, 1, 0, 5))
        self.assertEqual(dt.datetime.fromtimestamp(ts).year, 2026)

    def test_journal_entry(self):
        raw = json.dumps({"MESSAGE": "Accepted publickey for root from 10.1.1.1 port 2 ssh2",
                          "__REALTIME_TIMESTAMP": "1700000000000000", "__CURSOR": "s=abc"})
        auth, cursor = parse_journal_entry(raw)
        self.assertEqual((auth.user, auth.ts, cursor), ("root", 1700000000.0, "s=abc"))
        raw = json.dumps({"MESSAGE": list(b"Invalid user \xff from 10.0.0.2 port 3"), "__CURSOR": "c"})
        auth, _ = parse_journal_entry(raw)
        self.assertEqual(auth.ip, "10.0.0.2")
        self.assertEqual(parse_journal_entry("not json"), (None, None))


class WatcherTest(unittest.TestCase):
    def setUp(self):
        self.storage = Storage(":memory:")
        self.bus = EventBus(self.storage, "test")
        self.sink = Collect()
        self.bus.subscribe(self.sink)

    def make(self, **ssh):
        cfg = make_config(ssh={"bruteforce_threshold": 5, "bruteforce_window": 60, "bruteforce_cooldown": 600, **ssh})
        return SSHWatcher(cfg.ssh, self.storage, self.bus)

    def fail(self, w, ip, ts, user="root"):
        w.handle(parse_message(f"Failed password for {user} from {ip} port 1 ssh2", ts))

    def test_bruteforce_fires_once_per_cooldown(self):
        w = self.make()
        for i in range(12):
            self.fail(w, "198.51.100.1", 1000 + i)
        kinds = [e.kind for e in self.sink.events]
        self.assertEqual(kinds.count("ssh_bruteforce"), 1)
        self.assertEqual(self.storage.ssh_failure_total(0), 12)
        # after the cooldown a new burst alerts again
        for i in range(5):
            self.fail(w, "198.51.100.1", 2000 + i)
        self.assertEqual([e.kind for e in self.sink.events].count("ssh_bruteforce"), 2)

    def test_slow_failures_do_not_fire(self):
        w = self.make()
        for i in range(10):
            self.fail(w, "198.51.100.2", 1000 + i * 30)  # 2 per minute < 5 per minute
        self.assertNotIn("ssh_bruteforce", [e.kind for e in self.sink.events])

    def test_distributed_attack(self):
        w = self.make()
        for i in range(25):
            self.fail(w, f"198.51.100.{i}", 1000 + i)
        self.assertIn("ssh_mass_attack", [e.kind for e in self.sink.events])

    def test_login_notification_and_trusted(self):
        w = self.make(trusted_networks=["192.168.0.0/16"])
        w.handle(parse_message("Accepted publickey for a from 203.0.113.1 port 1 ssh2", 10))
        w.handle(parse_message("Accepted publickey for b from 192.168.1.5 port 1 ssh2", 11))
        logins = [e for e in self.sink.events if e.kind == "ssh_login"]
        self.assertEqual([e.data["notify"] for e in logins], [True, False])
        self.assertEqual(len(self.storage.recent_ssh_logins()), 2)

    def test_login_after_failures_is_critical(self):
        w = self.make()
        for i in range(3):
            self.fail(w, "203.0.113.9", 100 + i)
        w.handle(parse_message("Accepted password for root from 203.0.113.9 port 1 ssh2", 104))
        self.assertEqual(self.sink.events[-1].kind, "ssh_login_after_failures")
        self.assertEqual(self.sink.events[-1].severity, "critical")


class FileSourceTest(unittest.TestCase):
    def test_tail_follows_rotation(self):
        storage = Storage(":memory:")
        stop = threading.Event()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "auth.log")
            with open(path, "w") as fh:
                fh.write("Oct  4 10:00:00 h sshd[1]: Accepted password for old from 1.1.1.1 port 1 ssh2\n")
            src = FileSource(path, storage, stop, poll=0.05)
            got = []

            def consume():
                for auth in src.lines():
                    got.append(auth.user)
                    if len(got) == 3:
                        stop.set()

            t = threading.Thread(target=consume, daemon=True)
            t.start()
            time.sleep(0.2)
            with open(path, "a") as fh:  # appended line; partial write first
                fh.write("Oct  4 10:00:01 h sshd[1]: Accepted password for ")
                fh.flush()
                time.sleep(0.15)
                fh.write("new1 from 1.1.1.1 port 1 ssh2\n")
            time.sleep(0.2)
            os.rename(path, path + ".1")  # logrotate
            with open(path, "w") as fh:
                fh.write("Oct  4 10:00:02 h sshd[1]: Invalid user new2 from 2.2.2.2 port 2\n")
                fh.write("Oct  4 10:00:03 h sshd[1]: Accepted password for new3 from 2.2.2.2 port 2 ssh2\n")
            t.join(5)
            stop.set()
            self.assertEqual(got, ["new1", "new2", "new3"])  # the pre-existing line is skipped


if __name__ == "__main__":
    unittest.main()
