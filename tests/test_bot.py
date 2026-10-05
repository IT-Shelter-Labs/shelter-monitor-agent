import time
import unittest

from shelter_monitor.agent.app import Agent
from shelter_monitor.agent.bot.bot import parse_duration
from shelter_monitor.agent.storage import Storage
from tests.helpers import TOKEN, FakeAPI, make_config

ADMIN = 111
STRANGER = 999


def msg(text, user=ADMIN, chat_type="private"):
    return {"message": {"message_id": 1, "date": int(time.time()), "text": text,
                        "from": {"id": user, "username": "u"}, "chat": {"id": user, "type": chat_type}}}


def callback(data, user=ADMIN, text="📡 Устройства"):
    return {"callback_query": {"id": "cb1", "data": data, "from": {"id": user},
                               "message": {"message_id": 50, "text": text, "chat": {"id": user}}}}


class BotTest(unittest.TestCase):
    def setUp(self):
        cfg = make_config(actions={"containers": ["web"]}, docker={"socket": "/nonexistent.sock"},
                          lan={"subnets": ["192.168.1.0/24"], "active_probe": False},
                          connectivity={"targets": ["127.0.0.1:9"]})
        self.api = FakeAPI()
        self.agent = Agent(cfg, api=self.api, storage=Storage(":memory:"))  # type: ignore[arg-type]
        self.bot = self.agent.bot
        self.bot.async_work = False

    def test_unauthorized_user_is_denied_once(self):
        self.bot.handle_update(msg("/status", user=STRANGER))
        self.bot.handle_update(msg("/status", user=STRANGER))
        texts = self.api.texts("sendMessage")
        self.assertEqual(len(texts), 1)
        self.assertIn("Доступ запрещён", texts[0])
        self.assertIn(str(STRANGER), texts[0])
        events = self.agent.storage.recent_events(5)
        self.assertEqual(events[0].kind, "telegram_unauthorized")

    def test_unauthorized_callback(self):
        self.bot.handle_update(callback("act:c:0", user=STRANGER))
        self.assertEqual(self.agent.actions._pending, {})

    def test_id_command_is_public(self):
        self.bot.handle_update(msg("/id", user=STRANGER))
        self.assertIn(str(STRANGER), self.api.texts()[0])

    def test_stale_messages_ignored(self):
        update = msg("/status")
        update["message"]["date"] = int(time.time()) - 3600
        self.bot.handle_update(update)
        self.assertEqual(self.api.calls, [])

    def test_all_views_render(self):
        for cmd in ("/start", "/status", "/metrics", "/docker", "/services", "/ssh", "/events", "/devices",
                    "/notify", "/actions", "/help", "/check"):
            self.api.calls.clear()
            self.bot.handle_update(msg(cmd))
            texts = self.api.texts("sendMessage")
            self.assertTrue(texts, cmd)
            self.assertNotIn("Ошибка при получении данных", texts[-1], cmd)
        for view in ("status", "metrics", "events_all", "devices", "notify"):
            self.bot.handle_update(callback(f"v:{view}"))

    def test_free_text_is_never_executed(self):
        self.bot.handle_update(msg("rm -rf /"))
        self.assertIn("только команды", self.api.texts()[0])

    def test_mute_commands(self):
        self.bot.handle_update(msg("/mute 2h"))
        self.assertTrue(self.agent.settings.is_muted())
        self.assertAlmostEqual(self.agent.settings.mute_until - time.time(), 7200, delta=5)
        self.bot.handle_update(msg("/unmute"))
        self.assertFalse(self.agent.settings.is_muted())
        self.bot.handle_update(msg("/mute nonsense"))
        self.assertIn("Формат", self.api.texts()[-1])
        self.bot.handle_update(callback("mute:60"))
        self.assertTrue(self.agent.settings.is_muted())

    def test_category_toggle(self):
        self.bot.handle_update(callback("cat:docker"))
        self.assertIn("docker", self.agent.settings.disabled_categories)
        self.bot.handle_update(callback("cat:bogus"))
        self.assertEqual(self.agent.settings.disabled_categories, {"docker"})

    def test_action_flow_with_confirmation(self):
        restarted = []
        self.agent.actions._docker = type("D", (), {"restart": lambda self, n, timeout=20: restarted.append(n)})()
        self.bot.handle_update(callback("act:c:0"))
        confirm = self.api.calls[-1]
        self.assertEqual(confirm[0], "sendMessage")
        self.assertIn("Подтвердите", confirm[1]["text"])
        token_cb = confirm[1]["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
        self.assertTrue(token_cb.startswith("cf:"))
        self.assertEqual(restarted, [])  # nothing happens before confirmation
        self.bot.handle_update(callback(token_cb, user=STRANGER))
        self.assertEqual(restarted, [])
        self.bot.handle_update(callback(token_cb))
        self.assertEqual(restarted, ["web"])
        self.bot.handle_update(callback(token_cb))  # replay
        self.assertEqual(restarted, ["web"])
        self.assertIn("не найден", self.api.texts("editMessageText")[-1])

    def test_action_bad_index(self):
        self.bot.handle_update(callback("act:c:7"))
        self.bot.handle_update(callback("act:x:0"))
        self.bot.handle_update(callback("act:c:-1"))
        self.assertEqual(self.agent.actions._pending, {})

    def test_device_trust(self):
        self.agent.storage.upsert_device("aa:bb:cc:dd:ee:ff", "192.168.1.5", "", "eth0", time.time())
        self.bot.handle_update(callback("dev:trust:aa:bb:cc:dd:ee:ff"))
        self.assertTrue(self.agent.storage.get_device("aa:bb:cc:dd:ee:ff").trusted)
        self.bot.handle_update(callback("dev:trust:'; drop table devices"))
        self.assertEqual(self.agent.storage.device_count(), 1)

    def test_health_marker(self):
        import os
        import tempfile

        from shelter_monitor.agent.cli import main as cli_main

        with tempfile.TemporaryDirectory() as tmp:
            self.agent.health_file = os.path.join(tmp, "health")
            self.agent.bot.is_alive = lambda: True
            self.agent._touch_health()
            cfg_path = os.path.join(tmp, "config.toml")
            with open(cfg_path, "w") as fh:
                fh.write(f'[agent]\ndata_dir = "{tmp}"\n[telegram]\ntoken = "{TOKEN}"\nadmin_ids = [1]\n')
            self.assertEqual(cli_main(["-c", cfg_path, "healthcheck"]), 0)
            os.utime(self.agent.health_file, (0, 0))
            self.assertEqual(cli_main(["-c", cfg_path, "healthcheck"]), 1)

    def test_parse_duration(self):
        self.assertEqual(parse_duration(""), 3600)
        self.assertEqual(parse_duration("30m"), 1800)
        self.assertEqual(parse_duration("2ч"), 7200)
        self.assertEqual(parse_duration("1d"), 86400)
        self.assertEqual(parse_duration("15"), 900)
        self.assertIsNone(parse_duration("0"))
        self.assertIsNone(parse_duration("99d"))
        self.assertIsNone(parse_duration("abc"))


if __name__ == "__main__":
    unittest.main()
