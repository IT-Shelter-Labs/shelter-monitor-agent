import json
import os
import socketserver
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler

from shelter_monitor.agent.collectors.docker import DockerClient, DockerError
from shelter_monitor.agent.events import AlertTracker, EventBus
from shelter_monitor.agent.monitors.docker_watch import DockerMonitor
from shelter_monitor.agent.storage import Storage
from tests.helpers import make_config


class FakeDockerState:
    containers: list = []
    restarted: list = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def address_string(self):
        return "unix"

    def do_GET(self):
        if self.path.startswith("/v1.41/containers/json"):
            body = json.dumps(FakeDockerState.containers).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):
        if self.path.startswith("/v1.41/containers/web/restart"):
            FakeDockerState.restarted.append("web")
            self.send_response(204)
            self.end_headers()
        else:
            body = b'{"message":"No such container"}'
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def container(name, state, status):
    return {"Id": name * 6, "Names": [f"/{name}"], "Image": "img:latest", "State": state, "Status": status, "Created": 1}


class Collect:
    def __init__(self):
        self.events = []

    def handle(self, event):
        self.events.append(event)


class DockerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sock = os.path.join(self.tmp.name, "docker.sock")
        self.server = UnixServer(self.sock, Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.running = True
        self.client = DockerClient(self.sock, timeout=5)
        FakeDockerState.restarted = []

    def stop_server(self):
        if self.running:
            self.server.shutdown()
            self.server.server_close()
            self.running = False

    def tearDown(self):
        self.stop_server()
        self.tmp.cleanup()

    def test_client(self):
        FakeDockerState.containers = [container("web", "running", "Up 2 hours (unhealthy)")]
        cs = self.client.containers()
        self.assertEqual((cs[0].name, cs[0].health), ("web", "unhealthy"))
        self.client.restart("web")
        self.assertEqual(FakeDockerState.restarted, ["web"])
        with self.assertRaises(DockerError):
            self.client.restart("missing")

    def test_monitor_transitions(self):
        storage = Storage(":memory:")
        bus = EventBus(storage, "h")
        sink = Collect()
        bus.subscribe(sink)
        mon = DockerMonitor(make_config().docker, self.client, AlertTracker(bus), bus)

        FakeDockerState.containers = [container("web", "running", "Up 1 minute"), container("old", "exited", "Exited (0) 3 days ago")]
        mon.tick()
        self.assertEqual(sink.events, [])  # stopped-at-start container is not an alert

        FakeDockerState.containers = [container("web", "exited", "Exited (137) 5 seconds ago"),
                                      container("old", "exited", "Exited (0) 3 days ago")]
        mon.tick()
        mon.tick()
        self.assertEqual([e.kind for e in sink.events], ["container_down"])
        self.assertEqual(sink.events[0].severity, "critical")

        FakeDockerState.containers = [container("web", "running", "Up 1 second"), container("old", "exited", "Exited")]
        mon.tick()
        self.assertEqual(sink.events[-1].kind, "resolved")

        FakeDockerState.containers = [container("old", "exited", "Exited")]
        mon.tick()
        self.assertEqual(sink.events[-1].kind, "container_removed")

    def test_daemon_unreachable(self):
        storage = Storage(":memory:")
        bus = EventBus(storage, "h")
        sink = Collect()
        bus.subscribe(sink)
        self.stop_server()
        os.unlink(self.sock)
        open(self.sock, "w").close()  # socket path exists but nothing listens
        mon = DockerMonitor(make_config().docker, self.client, AlertTracker(bus), bus)
        mon.tick()
        self.assertEqual(sink.events[0].kind, "docker_down")


if __name__ == "__main__":
    unittest.main()
