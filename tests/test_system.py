import os
import tempfile
import unittest

from shelter_monitor.agent.collectors.system import CpuSampler, NetSampler, SystemCollector, take_snapshot
from shelter_monitor.agent.collectors.systemd import parse_show_output

PROC_FILES = {
    "stat": "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 50 0 50 350 50 0 0 0 0 0\n",
    "meminfo": "MemTotal:       8000000 kB\nMemFree:  1000000 kB\nMemAvailable:   2000000 kB\n"
               "SwapTotal:      1000000 kB\nSwapFree:        750000 kB\n",
    "loadavg": "0.50 1.25 2.00 1/123 4567\n",
    "uptime": "93784.12 300000.00\n",
    "net/dev": ("Inter-|   Receive                                                |  Transmit\n"
                " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
                "    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n"
                "  eth0: 5000 50 0 0 0 0 0 0 7000 70 0 0 0 0 0 0\n"
                "veth12: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n"),
    "net/route": ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                  "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
                  "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
                  "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"),
    "mounts": "/dev/sda1 / ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n/dev/sda1 /var/snap ext4 rw 0 0\n"
              "overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0\n",
    "sys/kernel/random/boot_id": "abcd-1234\n",
}


class SystemCollectorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        for rel, content in PROC_FILES.items():
            path = os.path.join(self.tmp.name, "proc", rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(content)
        zone = os.path.join(self.tmp.name, "sys", "class", "thermal", "thermal_zone0")
        os.makedirs(zone)
        with open(os.path.join(zone, "temp"), "w") as fh:
            fh.write("54321\n")
        self.col = SystemCollector(proc=os.path.join(self.tmp.name, "proc"), sys=os.path.join(self.tmp.name, "sys"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_cpu_times(self):
        self.assertEqual(self.col.cpu_times(), (800, 1000))

    def test_memory(self):
        mem = self.col.memory()
        self.assertEqual(mem.total, 8000000 * 1024)
        self.assertAlmostEqual(mem.percent, 75.0)
        self.assertAlmostEqual(mem.swap_percent, 25.0)

    def test_load_uptime_bootid(self):
        self.assertEqual(self.col.load(), (0.5, 1.25, 2.0))
        self.assertAlmostEqual(self.col.uptime(), 93784.12)
        self.assertEqual(self.col.boot_id(), "abcd-1234")

    def test_routes(self):
        self.assertEqual(self.col.default_route(), ("eth0", "192.168.1.1"))
        self.assertEqual(self.col.ipv4_routes(), [("eth0", "192.168.1.0/24"), ("docker0", "172.17.0.0/16")])

    def test_mounts_filtering(self):
        self.assertEqual(self.col.mounts(), [("/dev/sda1", "/", "ext4")])

    def test_net_sampler_skips_virtual(self):
        rates = NetSampler(self.col).rates()
        self.assertEqual([r.iface for r in rates], ["eth0"])
        self.assertEqual((rates[0].rx_bytes, rates[0].tx_bytes), (5000, 7000))

    def test_temperature(self):
        self.assertEqual(self.col.temperature(), 54.3)

    def test_cpu_sampler(self):
        sampler = CpuSampler(self.col)
        sampler.percent(min_window=0)
        with open(os.path.join(self.tmp.name, "proc", "stat"), "w") as fh:
            fh.write("cpu  150 0 150 800 100 0 0 0 0 0\n")  # +100 busy, +100 idle
        self.assertAlmostEqual(sampler.percent(), 50.0)

    def test_real_snapshot(self):
        col = SystemCollector()
        snap = take_snapshot(col, CpuSampler(col), NetSampler(col))
        self.assertGreater(snap.memory.total, 0)
        self.assertGreater(snap.uptime, 0)
        summary = snap.summary()
        self.assertIn("disk_max_percent", summary)


class SystemdParseTest(unittest.TestCase):
    def test_parse_show(self):
        out = ("Id=ssh.service\nLoadState=loaded\nActiveState=active\nSubState=running\nDescription=OpenBSD Secure Shell server\n\n"
               "Id=nope.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nDescription=nope.service\n")
        units = parse_show_output(out)
        self.assertEqual(len(units), 2)
        self.assertTrue(units[0].ok and units[0].exists)
        self.assertFalse(units[1].exists)



class HostRootTest(unittest.TestCase):
    """Agent running in a container with the host's / mounted at host_root."""

    def test_mounts_and_identity_from_host_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = os.path.join(tmp, "host")
            os.makedirs(os.path.join(host, "etc"))
            os.makedirs(os.path.join(host, "srv"))
            with open(os.path.join(host, "etc", "hostname"), "w") as fh:
                fh.write("real-server\n")
            with open(os.path.join(host, "etc", "os-release"), "w") as fh:
                fh.write('PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n')
            proc = os.path.join(tmp, "proc")
            os.makedirs(proc)
            with open(os.path.join(proc, "mounts"), "w") as fh:
                fh.write("overlay / overlay rw 0 0\n"
                         "/dev/sda1 /etc/hosts ext4 rw 0 0\n"
                         f"/dev/sda1 {host} ext4 ro 0 0\n"
                         f"proc {host}/proc proc rw 0 0\n"
                         f"/dev/sdb1 {host}/srv xfs ro 0 0\n"
                         f"/dev/sda1 {host}/var/lib/docker ext4 ro 0 0\n")
            col = SystemCollector(proc=proc, host_root=host + "/")
            self.assertEqual(col.mounts(), [("/dev/sda1", "/", "ext4"), ("/dev/sdb1", "/srv", "xfs")])
            disks = col.disks()
            self.assertEqual([d.mount for d in disks], ["/", "/srv"])  # statvfs went to the host paths
            self.assertEqual(col.hostname(), "real-server")
            self.assertEqual(col.os_name(), "Debian GNU/Linux 12 (bookworm)")
            self.assertEqual(col.host_path("/"), host)
            self.assertEqual(col.host_path("/srv"), host + "/srv")


if __name__ == "__main__":
    unittest.main()
