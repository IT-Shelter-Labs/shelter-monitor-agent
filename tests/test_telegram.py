import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from shelter_monitor.agent.app import Agent
from shelter_monitor.agent.storage import Storage
from shelter_monitor.telegram import Outbox, TelegramAPI, TelegramError
from tests.helpers import TOKEN, make_config


class FakeBotAPI:
    def __init__(self):
        self.calls = []
        self.updates = []
        self.fail_next_send = 0
        self.lock = threading.Lock()

    def handle(self, method, params):
        with self.lock:
            self.calls.append((method, params))
            if method == "sendMessage" and self.fail_next_send:
                self.fail_next_send -= 1
                return 429, {"ok": False, "error_code": 429, "description": "Too Many Requests",
                             "parameters": {"retry_after": 0.1}}
            if method == "getUpdates":
                offset = params.get("offset") or 0
                pending = [u for u in self.updates if u["update_id"] >= offset]
                if not pending:
                    time.sleep(0.05)
                return 200, {"ok": True, "result": pending}
            if method == "getMe":
                return 200, {"ok": True, "result": {"id": 1, "username": "test_bot"}}
            return 200, {"ok": True, "result": {"message_id": len(self.calls)}}

    def sent(self):
        with self.lock:
            return [p["text"] for m, p in self.calls if m == "sendMessage"]


def start_server(fake):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            expected = f"/bot{TOKEN}/"
            if not self.path.startswith(expected):
                code, payload = 401, {"ok": False, "error_code": 401, "description": "Unauthorized"}
            else:
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                code, payload = fake.handle(self.path[len(expected):], json.loads(body or b"{}"))
            data = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class TelegramClientTest(unittest.TestCase):
    def setUp(self):
        self.fake = FakeBotAPI()
        self.server, self.url = start_server(self.fake)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def wait_for(self, cond, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if cond():
                return True
            time.sleep(0.02)
        return False

    def test_api_errors_do_not_leak_token(self):
        api = TelegramAPI("999:wrongtokenwrongtokenwrongtoken", self.url)
        with self.assertRaises(TelegramError) as ctx:
            api.get_me()
        self.assertEqual(ctx.exception.code, 401)
        self.assertNotIn("wrongtoken", str(ctx.exception))
        self.assertEqual(TelegramAPI(TOKEN, self.url).get_me()["username"], "test_bot")

    def test_outbox_retries_429(self):
        self.fake.fail_next_send = 2
        outbox = Outbox(TelegramAPI(TOKEN, self.url), min_interval=0)
        outbox.start()
        outbox.send(1, "hello")
        self.assertTrue(self.wait_for(lambda: self.fake.sent().count("hello") == 3))
        outbox.stop()

    def test_agent_polling_end_to_end(self):
        cfg = make_config(docker={"socket": "/nonexistent.sock"}, lan={"enabled": False}, ssh={"enabled": False},
                          connectivity={"enabled": False}, telegram={"api_url": self.url})
        agent = Agent(cfg, storage=Storage(":memory:"))
        self.fake.updates.append({"update_id": 10, "message": {
            "message_id": 1, "date": int(time.time()), "text": "/status",
            "from": {"id": 111}, "chat": {"id": 111, "type": "private"}}})
        agent.start()
        try:
            self.assertTrue(self.wait_for(lambda: any("Агент мониторинга запущен" in t for t in self.fake.sent())))
            self.assertTrue(self.wait_for(lambda: any("Аптайм" in t for t in self.fake.sent())))
            # the processed update is acknowledged through the offset
            self.assertTrue(self.wait_for(lambda: any(m == "getUpdates" and p.get("offset") == 11
                                                      for m, p in list(self.fake.calls))))
        finally:
            agent._stop.set()
            agent.stop()
        self.assertTrue(any("остановлен" in t for t in self.fake.sent()))


if __name__ == "__main__":
    unittest.main()
