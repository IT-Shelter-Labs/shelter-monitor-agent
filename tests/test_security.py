import os
import tempfile
import unittest

from shelter_monitor.agent.events import EventBus
from shelter_monitor.agent.security import (ConnectionMonitor, FirewallWatcher, parse_firewall_line,
                                            parse_firewall_message, parse_proc_net_tcp)
from shelter_monitor.agent.storage import Storage
from tests.helpers import make_config

UFW = ("[UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:aa:bb:cc SRC=203.0.113.7 DST=198.51.100.2 LEN=40 TOS=0x00 "
       "PREC=0x00 TTL=242 ID=54321 PROTO=TCP SPT=41234 DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0")


class Collect:
    def __init__(self):
        self.events = []

    def handle(self, event):
        self.events.append(event)


class FirewallParseTest(unittest.TestCase):
    def test_ufw_block(self):
        hit = parse_firewall_message(UFW.format(port=23), 100.0)
        self.assertEqual((hit.src, hit.dport, hit.proto, hit.prefix, hit.ts), ("203.0.113.7", 23, "TCP", "UFW BLOCK", 100.0))

    def test_ignored(self):
        self.assertIsNone(parse_firewall_message(UFW.replace("BLOCK", "ALLOW").format(port=22)))
        self.assertIsNone(parse_firewall_message(UFW.replace("BLOCK", "AUDIT").format(port=22)))
        outbound = "[UFW BLOCK] IN= OUT=eth0 SRC=10.0.0.2 DST=8.8.8.8 PROTO=UDP SPT=1 DPT=53"
        self.assertIsNone(parse_firewall_message(outbound))
        self.assertIsNone(parse_firewall_message("usb 1-1: new high-speed USB device"))

    def test_iptables_prefix_and_kern_log_line(self):
        msg = "IPTables-Dropped: IN=ens3 OUT= MAC=00 SRC=192.0.2.1 DST=192.0.2.2 LEN=60 PROTO=TCP SPT=5 DPT=3389"
        self.assertEqual(parse_firewall_message(msg).dport, 3389)
        line = "Oct  6 10:00:00 host kernel: [12345.678901] " + UFW.format(port=445)
        hit = parse_firewall_line(line)
        self.assertEqual((hit.dport, hit.prefix), (445, "UFW BLOCK"))
        self.assertIsNone(parse_firewall_line("Oct  6 10:00:00 host sshd[1]: " + UFW.format(port=1)))

    def test_icmp_without_port(self):
        hit = parse_firewall_message("[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=198.51.100.2 PROTO=ICMP TYPE=8 CODE=0")
        self.assertEqual((hit.proto, hit.dport), ("ICMP", None))


class PortScanTest(unittest.TestCase):
    def test_scan_detected_once(self):
        bus = EventBus(Storage(":memory:"), "h")
        sink = Collect()
        bus.subscribe(sink)
        w = FirewallWatcher(make_config(firewall={"scan_ports": 5, "scan_window": 60}).firewall, None, bus)
        for i, port in enumerate([22, 23, 80, 443, 3389, 5900, 8080]):
            w.handle(parse_firewall_message(UFW.format(port=port), 1000.0 + i))
        for i in range(10):  # same port again and again is not a scan
            w.handle(parse_firewall_message(UFW.replace("203.0.113.7", "203.0.113.8").format(port=22), 1000.0 + i))
        scans = [e for e in sink.events if e.kind == "port_scan"]
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].data["ip"], "203.0.113.7")
        stats = w.stats(0)
        self.assertEqual((stats["total"], stats["ips"]), (17, 2))
        self.assertEqual(stats["top_ports"][0], (22, 11))

    def test_file_source_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ufw.log")
            open(path, "w").close()
            w = FirewallWatcher(make_config(firewall={"source": "file", "log_file": path}).firewall, Storage(":memory:"),
                                EventBus(Storage(":memory:"), "h"))
            self.assertEqual(w.select_source().name, "file")


TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   113        0 1 1
   1: 0201A8C0:1538 0771000A:D431 01 00000000:00000000 00:00000000 00000000   113        0 2 1
   2: 0201A8C0:1538 070071CB:D431 01 00000000:00000000 00:00000000 00000000   113        0 3 1
   3: 0201A8C0:0016 080071CB:D432 01 00000000:00000000 00:00000000 00000000     0        0 4 1
   4: 0201A8C0:9C40 090071CB:1538 01 00000000:00000000 00:00000000 00000000     0        0 5 1
"""
TCP6 = """  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:0CEA 00000000000000000000000000000000:0000 0A 0 0 0 0 0 0
   1: 0000000000000000FFFF00000201A8C0:0CEA 0000000000000000FFFF00000A0071CB:D431 01 0 0 0 0 0 0
"""


class ConnectionsTest(unittest.TestCase):
    def test_parse(self):
        socks = parse_proc_net_tcp(TCP)
        self.assertEqual((socks[0].local_port, socks[0].state), (5432, "0A"))
        self.assertEqual((socks[2].remote_ip, socks[2].remote_port), ("203.113.0.7", 54321))
        v6 = parse_proc_net_tcp(TCP6)
        self.assertEqual((v6[1].remote_ip, v6[1].local_port), ("203.113.0.10", 3306))

    def test_new_public_connection_to_watched_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "net"))
            with open(os.path.join(tmp, "net", "tcp"), "w") as fh:
                fh.write(TCP)
            with open(os.path.join(tmp, "net", "tcp6"), "w") as fh:
                fh.write(TCP6)
            bus = EventBus(Storage(":memory:"), "h")
            sink = Collect()
            bus.subscribe(sink)
            cfg = make_config(connections={"ports": [5432, 3306]})
            mon = ConnectionMonitor(cfg.connections, bus, ["203.113.0.10/32"], proc=tmp)
            mon.tick()
            mon.tick()
        # 10.0.113.7 is private, 203.113.0.10 trusted, port 22 not watched, 40000 is an outgoing connection
        self.assertEqual([(e.data["ip"], e.data["port"]) for e in sink.events], [("203.113.0.7", 5432)])
        self.assertEqual(mon.listening, {5432, 3306})


if __name__ == "__main__":
    unittest.main()
