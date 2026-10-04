import os
import tempfile
import unittest
from unittest import mock

from shelter_monitor.agent.collectors.system import SystemCollector
from shelter_monitor.agent.events import EventBus
from shelter_monitor.agent.lan import LANScanner, is_random_mac, parse_proc_arp
from shelter_monitor.agent.storage import Storage
from tests.helpers import make_config

ARP_HEADER = "IP address       HW type     Flags       HW address            Mask     Device\n"


def arp_line(ip, mac, flags="0x2", dev="eth0"):
    return f"{ip:<17}0x1         {flags:<12}{mac}     *        {dev}\n"


class Collect:
    def __init__(self):
        self.events = []

    def handle(self, event):
        self.events.append(event)


class LANTest(unittest.TestCase):
    def test_parse_proc_arp(self):
        text = (ARP_HEADER + arp_line("192.168.1.1", "AA:BB:CC:00:00:01") + arp_line("192.168.1.9", "00:00:00:00:00:00", "0x0")
                + arp_line("192.168.1.7", "aa:bb:cc:00:00:07", "0x0"))
        nbs = parse_proc_arp(text)
        self.assertEqual([(n.ip, n.mac) for n in nbs], [("192.168.1.1", "aa:bb:cc:00:00:01")])

    def test_random_mac(self):
        self.assertTrue(is_random_mac("da:a1:19:00:00:01"))
        self.assertFalse(is_random_mac("00:1a:2b:3c:4d:5e"))

    def test_baseline_then_new_device(self):
        storage = Storage(":memory:")
        bus = EventBus(storage, "h")
        sink = Collect()
        bus.subscribe(sink)
        with tempfile.TemporaryDirectory() as tmp:
            arp = os.path.join(tmp, "arp")
            with open(arp, "w") as fh:
                fh.write(ARP_HEADER + arp_line("192.168.1.1", "00:11:22:33:44:01") + arp_line("10.0.0.5", "00:11:22:33:44:99"))
            cfg = make_config(lan={"subnets": ["192.168.1.0/24"], "active_probe": False})
            scanner = LANScanner(cfg.lan, SystemCollector(), storage, bus, arp_path=arp)
            with mock.patch("time.sleep"):
                scanner.tick()
            self.assertEqual([e.kind for e in sink.events], ["lan_baseline"])
            self.assertEqual(storage.device_count(), 1)  # 10.0.0.5 is outside the subnet
            self.assertTrue(storage.list_devices()[0].trusted)

            with open(arp, "a") as fh:
                fh.write(arp_line("192.168.1.50", "da:00:00:00:00:50"))
            with mock.patch("shelter_monitor.agent.lan.reverse_dns", return_value="phone.lan"):
                scanner.tick()
                scanner.tick()  # seen again: no second notification
            new = [e for e in sink.events if e.kind == "lan_new_device"]
            self.assertEqual(len(new), 1)
            self.assertIn("phone.lan", new[0].body)
            self.assertIn("Случайный", new[0].body)
            self.assertEqual(new[0].buttons[0][0][1], "dev:trust:da:00:00:00:00:50")
            self.assertFalse(storage.get_device("da:00:00:00:00:50").trusted)

    def test_auto_subnet_skips_virtual_and_public(self):
        cfg = make_config()
        col = mock.Mock()
        col.default_route.return_value = ("eth0", "192.168.1.1")
        col.ipv4_routes.return_value = [("eth0", "192.168.1.0/24"), ("docker0", "172.17.0.0/16"), ("eth0", "45.10.20.0/24")]
        scanner = LANScanner(cfg.lan, col, Storage(":memory:"), mock.Mock())
        self.assertEqual([str(n) for _, n in scanner.subnets()], ["192.168.1.0/24"])


if __name__ == "__main__":
    unittest.main()
