import ipaddress
import os
import tempfile
import time
import unittest
from unittest import mock

from shelter_monitor.agent import runtime
from shelter_monitor.agent.collectors.systemd import (ServiceProbe, SystemdClient, SystemdError, candidate_processes,
                                                      host_proc_root, status_from_processes)
from shelter_monitor.agent.events import EventBus
from shelter_monitor.agent.lan import LANScanner
from shelter_monitor.agent.storage import Storage
from tests.helpers import make_config


def fake_proc(tmp, processes):
    for pid, comm in processes.items():
        os.makedirs(os.path.join(tmp, str(pid)))
        with open(os.path.join(tmp, str(pid), "comm"), "w") as fh:
            fh.write(comm + "\n")


class SystemctlErrorTest(unittest.TestCase):
    def test_failure_is_an_error_not_missing_units(self):
        client = SystemdClient()
        failed = mock.Mock(returncode=1, stdout="", stderr="Failed to connect to bus: No such file or directory\n")
        with mock.patch("subprocess.run", return_value=failed):
            with self.assertRaises(SystemdError) as ctx:
                client.status(["cron.service"])
        self.assertIn("Failed to connect to bus", str(ctx.exception))

    def test_not_found_is_reported_as_missing(self):
        out = "Id=nope.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n"
        with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0, stdout=out, stderr="")):
            units = SystemdClient().status(["nope.service"])
        self.assertFalse(units[0].exists)


class ProcessFallbackTest(unittest.TestCase):
    def test_candidates(self):
        self.assertEqual(candidate_processes("ssh.service"), ["sshd"])
        self.assertEqual(candidate_processes("cron.service"), ["cron", "crond"])
        self.assertEqual(candidate_processes("myapp.service"), ["myapp", "myappd"])

    def test_status_from_processes(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_proc(tmp, {1: "systemd", 100: "cron", 200: "sshd"})
            self.assertEqual(host_proc_root(), host_proc_root())  # does not crash on the real system
            units = status_from_processes(["cron.service", "nginx.service", "ufw.service"], tmp)
        self.assertEqual([(u.name, u.active_state) for u in units],
                         [("cron.service", "active"), ("nginx.service", "inactive"), ("ufw.service", "unknown")])
        self.assertTrue(all(u.approximate for u in units))

    def test_probe_falls_back_to_host_processes(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_proc(os.path.join(tmp, "proc"), {1: "systemd", 100: "cron"})
            client = mock.Mock()
            client.available.return_value = True
            client.status.side_effect = SystemdError("Access denied")
            probe = ServiceProbe(client, host_root=tmp)
            units, source, error = probe.status(["cron.service"])
        self.assertEqual((source, error), ("processes", "Access denied"))
        self.assertTrue(units[0].ok)
        self.assertEqual(probe.failed_units(), [])


class RuntimeTest(unittest.TestCase):
    def write_dev(self, tmp, names):
        os.makedirs(os.path.join(tmp, "net"), exist_ok=True)
        with open(os.path.join(tmp, "net", "dev"), "w") as fh:
            fh.write("h1\nh2\n" + "".join(f"{n}: 0 0 0 0 0 0 0 0 0 0\n" for n in names))

    def test_host_network_detection(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(runtime, "in_container", return_value=True):
            self.write_dev(tmp, ["lo", "eth0"])
            self.assertFalse(runtime.uses_host_network(tmp))
            self.write_dev(tmp, ["lo", "eth0", "eth1"])  # container attached to two docker networks
            self.assertFalse(runtime.uses_host_network(tmp))
            self.write_dev(tmp, ["lo", "eth0", "docker0", "veth1a2b"])
            self.assertTrue(runtime.uses_host_network(tmp))
            self.write_dev(tmp, ["lo", "ens3"])
            self.assertTrue(runtime.uses_host_network(tmp))
        with mock.patch.object(runtime, "in_container", return_value=False):
            self.assertTrue(runtime.uses_host_network("/nonexistent"))


class LANDockerTest(unittest.TestCase):
    def make(self, routes, docker_nets, host_net=True):
        storage = Storage(":memory:")
        col = mock.Mock()
        col.default_route.return_value = ("eth0", "172.20.0.1")
        col.ipv4_routes.return_value = routes
        docker = mock.Mock()
        docker.available.return_value = True
        docker.networks.return_value = docker_nets
        scanner = LANScanner(make_config().lan, col, storage, EventBus(storage, "h"), docker=docker)
        patcher = mock.patch("shelter_monitor.agent.lan.uses_host_network", return_value=host_net)
        patcher.start()
        self.addCleanup(patcher.stop)
        return scanner, storage

    def test_docker_network_is_not_lan(self):
        scanner, storage = self.make([("eth0", "172.20.0.0/16")], [("vpn-bots_bots", "172.20.0.0/16")])
        self.assertEqual(scanner.subnets(), [])
        self.assertIn("Docker", scanner.disabled_reason)
        storage.upsert_device("fa:2c:82:0c:0d:a9", "172.20.0.1", "", "eth0", time.time())
        storage.upsert_device("00:11:22:33:44:55", "192.168.1.10", "", "eth0", time.time())
        scanner.tick()
        self.assertEqual([d.ip for d in storage.list_devices()], ["192.168.1.10"])  # container entries purged

    def test_bridged_container(self):
        scanner, _ = self.make([("eth0", "172.20.0.0/16")], [], host_net=False)
        self.assertEqual(scanner.subnets(), [])
        self.assertIn("network_mode: host", scanner.disabled_reason)

    def test_real_lan_kept(self):
        scanner, _ = self.make([("eth0", "192.168.1.0/24")], [("bridge", "172.17.0.0/16")])
        self.assertEqual([n for _, n in scanner.subnets()], [ipaddress.IPv4Network("192.168.1.0/24")])
        self.assertEqual(scanner.disabled_reason, "")



class OwnContainerTest(unittest.TestCase):
    def test_mountinfo(self):
        own, other = "a" * 64, "b" * 64
        text = (f"100 90 0:50 / / rw - overlay overlay rw\n"
                f"200 100 8:1 /var/lib/docker/containers/{other}/hostname /host/var/lib/x rw - ext4 /dev/sda1 rw\n"
                f"300 100 8:1 /var/lib/docker/containers/{own}/resolv.conf /etc/resolv.conf rw - ext4 /dev/sda1 rw\n")
        self.assertEqual(runtime.container_id_from_mountinfo(text), own)
        self.assertEqual(runtime.container_id_from_mountinfo("1 2 3 / / rw\n"), "")


if __name__ == "__main__":
    unittest.main()
