import os
import tempfile
import time
import unittest
from unittest import mock

from shelter_monitor.agent.app import Agent
from shelter_monitor.agent.bot.bot import entities_to_html, parse_duration
from shelter_monitor.agent.collectors.docker import Container
from shelter_monitor.agent.storage import Storage
from tests.helpers import TOKEN, FakeAPI, make_config

ADMIN = 111
STRANGER = 999
MAC = "aa:bb:cc:dd:ee:ff"


def msg(text, user=ADMIN, chat_type="private"):
    return {"message": {"message_id": 1, "date": int(time.time()), "text": text,
                        "from": {"id": user, "username": "u"}, "chat": {"id": user, "type": chat_type}}}


def callback(data, user=ADMIN, text="📡 Устройства", entities=None):
    return {"callback_query": {"id": "cb1", "data": data, "from": {"id": user, "username": "admin"},
                               "message": {"message_id": 50, "text": text, "chat": {"id": user},
                                           "entities": entities or []}}}


class FakeDocker:
    socket_path = "/fake.sock"

    def __init__(self):
        self.calls = []
        self.items = [Container("abc123", "web", "nginx:latest", "running", "Up 2 hours", 0),
                      Container("def456", "db", "postgres:16", "exited", "Exited (1) 5 minutes ago", 0)]

    def available(self):
        return True

    def containers(self):
        return list(self.items)

    def container(self, name):
        return next((c for c in self.items if c.name == name or c.id == name), None)

    def logs(self, name, tail=40):
        return "line1\nline2 <b>\n"

    def restart(self, name, timeout=20):
        self.calls.append(("restart", name))

    def start(self, name):
        self.calls.append(("start", name))

    def version(self):
        return {"Version": "29.0"}

    def networks(self):
        return []


class BotTest(unittest.TestCase):
    def setUp(self):
        cfg = make_config(docker={"socket": "/nonexistent.sock"},
                          lan={"subnets": ["192.168.1.0/24"], "active_probe": False},
                          connectivity={"targets": ["127.0.0.1:9"]}, firewall={"source": "file", "log_file": "/nonexistent"})
        self.api = FakeAPI()
        self.agent = Agent(cfg, api=self.api, storage=Storage(":memory:"))  # type: ignore[arg-type]
        self.docker = FakeDocker()
        self.agent.docker = self.docker  # type: ignore[assignment]
        self.agent.actions._docker = self.docker  # type: ignore[assignment]
        self.agent.actions.own_container = ""
        self.bot = self.agent.bot
        self.bot.async_work = False

    def answers(self):
        return [p for m, p in self.api.calls if m == "answerCallbackQuery"]

    def press(self, data, **kw):
        """Press a button and assert it was answered exactly once."""
        before = len(self.answers())
        self.bot.handle_update(callback(data, **kw))
        self.assertEqual(len(self.answers()) - before, 1, f"{data}: must be answered exactly once")
        return self.api.calls[-1]

    # -- access ---------------------------------------------------------------------

    def test_unauthorized_user_is_denied_once(self):
        self.bot.handle_update(msg("/status", user=STRANGER))
        self.bot.handle_update(msg("/status", user=STRANGER))
        texts = self.api.texts("sendMessage")
        self.assertEqual(len(texts), 1)
        self.assertIn("Доступ запрещён", texts[0])
        self.assertIn(str(STRANGER), texts[0])
        self.assertEqual(self.agent.storage.recent_events(5)[0].kind, "telegram_unauthorized")

    def test_unauthorized_callback(self):
        self.bot.handle_update(callback("a:cr:web", user=STRANGER))
        self.assertEqual(self.agent.actions._pending, {})
        self.assertTrue(self.answers()[-1]["alert"])

    def test_id_command_is_public(self):
        self.bot.handle_update(msg("/id", user=STRANGER))
        self.assertIn(str(STRANGER), self.api.texts()[0])

    def test_stale_messages_ignored(self):
        update = msg("/status")
        update["message"]["date"] = int(time.time()) - 3600
        self.bot.handle_update(update)
        self.assertEqual(self.api.calls, [])

    def test_free_text_is_never_executed(self):
        self.bot.handle_update(msg("rm -rf /"))
        self.assertIn("только команды", self.api.texts()[0])

    # -- views ------------------------------------------------------------------------

    def test_all_commands_render(self):
        for cmd in ("/start", "/status", "/metrics", "/docker", "/services", "/ssh", "/security", "/events",
                    "/devices", "/notify", "/actions", "/diag", "/help", "/check"):
            self.api.calls.clear()
            self.bot.handle_update(msg(cmd))
            texts = self.api.texts()
            self.assertTrue(texts, cmd)
            self.assertNotIn("Ошибка при получении данных", texts[-1], cmd)

    def test_view_buttons_edit_in_place(self):
        for view in ("status", "metrics", "docker:0", "services", "ssh", "security", "events_all", "devices",
                     "notify", "actions", "diag"):
            self.press(f"v:{view}")
            params = self.api.calls[-2][1]
            self.assertEqual(self.api.calls[-2][0], "editMessageText", view)
            self.assertEqual(params["message_id"], 50)
            self.assertNotIn("Ошибка", params["text"], view)

    def test_open_buttons_send_new_message(self):
        self.press("o:devices", text="⚠️ Новое устройство в локальной сети")
        self.assertEqual(self.api.calls[-2][0], "sendMessage")  # the notification stays untouched
        self.assertFalse(any(m == "editMessageText" for m, _ in self.api.calls))

    def test_unknown_and_stale_buttons_are_answered(self):
        for data in ("v:nope", "zzz", "act:c:0", "a:cr:", "a:sr:bad name", "c:$(id)", "dev:trust:xx"):
            self.press(data)

    def test_check_button_shows_result(self):
        self.press("chk", text="🖥 host")
        edits = self.api.texts("editMessageText")
        self.assertIn("Выполняю", edits[0])
        self.assertIn("Проверка выполнена", edits[-1])

    # -- notifications settings ------------------------------------------------------------

    def test_mute_commands(self):
        self.bot.handle_update(msg("/mute 2h"))
        self.assertTrue(self.agent.settings.is_muted())
        self.assertAlmostEqual(self.agent.settings.mute_until - time.time(), 7200, delta=5)
        self.press("unmute:msg", text="🔕 Уведомления выключены до …")
        self.assertFalse(self.agent.settings.is_muted())
        self.assertIn("снова включены", self.api.texts("editMessageText")[-1])
        self.bot.handle_update(msg("/mute nonsense"))
        self.assertIn("Формат", self.api.texts()[-1])
        self.press("mute:60")
        self.assertTrue(self.agent.settings.is_muted())

    def test_category_toggle(self):
        self.press("cat:docker")
        self.assertIn("docker", self.agent.settings.disabled_categories)
        self.press("cat:bogus")
        self.assertEqual(self.agent.settings.disabled_categories, {"docker"})

    # -- devices ---------------------------------------------------------------------------

    def test_trust_from_notification_updates_that_message(self):
        self.agent.storage.upsert_device(MAC, "192.168.1.5", "phone", "eth0", time.time())
        self.press(f"dev:trust:{MAC}", text="⚠️ Новое устройство в локальной сети")
        self.assertTrue(self.agent.storage.get_device(MAC).trusted)
        method, params = self.api.calls[-2]
        self.assertEqual(method, "editMessageText")
        self.assertIn("Доверенное устройство", params["text"])
        self.assertIn("@admin", params["text"])
        buttons = [b["callback_data"] for row in params["reply_markup"]["inline_keyboard"] for b in row]
        self.assertIn(f"dev:untrust:{MAC}", buttons)
        self.assertNotIn(f"dev:trust:{MAC}", buttons)
        self.press(f"dev:forget:{MAC}", text="✅ Доверенное устройство")
        self.assertIsNone(self.agent.storage.get_device(MAC))
        self.assertIn("забыто", self.api.texts("editMessageText")[-1])

    def test_trust_from_list_rerenders_list(self):
        self.agent.storage.upsert_device(MAC, "192.168.1.5", "", "eth0", time.time())
        self.press(f"devv:trust:{MAC}")
        self.assertTrue(self.api.texts("editMessageText")[-1].startswith("📡"))
        self.agent.storage.upsert_device("aa:bb:cc:dd:ee:01", "192.168.1.6", "", "eth0", time.time())
        self.press("devv:trustall")
        self.assertTrue(all(d.trusted for d in self.agent.storage.list_devices()))
        self.press("devv:forgetall")
        self.assertIn("Забыть все", self.api.texts("editMessageText")[-1])
        self.assertEqual(self.agent.storage.device_count(), 2)  # asked, not yet done
        self.press("devv:forgetall:yes")
        self.assertEqual(self.agent.storage.device_count(), 0)

    def test_device_injection_rejected(self):
        self.agent.storage.upsert_device(MAC, "192.168.1.5", "", "eth0", time.time())
        self.press("dev:trust:'; drop table devices")
        self.assertEqual(self.agent.storage.device_count(), 1)

    def test_lan_scan_refreshes_list(self):
        with mock.patch.object(self.agent, "run_task") as run_task:
            self.press("lan:scan")
        run_task.assert_called_once_with("lan")
        self.assertTrue(self.api.texts("editMessageText")[-1].startswith("📡"))

    # -- docker ----------------------------------------------------------------------------

    def test_container_card_and_logs(self):
        self.press("c:db")
        text = self.api.texts("editMessageText")[-1]
        self.assertIn("db", text)
        buttons = [b["callback_data"] for row in self.api.calls[-2][1]["reply_markup"]["inline_keyboard"] for b in row]
        self.assertIn("a:cs:db", buttons)
        self.assertIn("cl:db", buttons)
        self.press("cl:db", text="🔴 db")
        self.assertEqual(self.api.calls[-2][0], "sendMessage")
        self.assertIn("&lt;b&gt;", self.api.calls[-2][1]["text"])  # log content is escaped

    def test_action_flow_with_confirmation(self):
        self.press("a:cr:web", text="🟢 web")
        method, params = self.api.calls[-2]
        self.assertEqual(method, "sendMessage")
        self.assertIn("Подтвердите", params["text"])
        token_cb = params["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
        self.assertTrue(token_cb.startswith("cf:"))
        self.assertEqual(self.docker.calls, [])  # nothing happens before confirmation
        self.bot.handle_update(callback(token_cb, user=STRANGER))
        self.assertEqual(self.docker.calls, [])
        self.press(token_cb, text="⚠️ Подтвердите действие")
        self.assertEqual(self.docker.calls, [("restart", "web")])
        self.assertIn("Перезапустить контейнер web", self.api.texts("editMessageText")[-1])
        self.press(token_cb)  # replay
        self.assertEqual(self.docker.calls, [("restart", "web")])
        self.assertIn("не найден", self.api.texts("editMessageText")[-1])

    def test_expired_confirmation_loses_buttons(self):
        with mock.patch("threading.Timer") as timer:
            self.press("a:cr:web")
        expire = timer.call_args.args[1]
        token = next(iter(self.agent.actions._pending))
        self.agent.actions._pending[token].expires = time.time() - 1
        expire()
        self.assertIn("истекло", self.api.texts("editMessageText")[-1])
        self.assertEqual(self.agent.actions._pending, {})

    def test_cancel(self):
        self.press("a:cr:web")
        token = next(iter(self.agent.actions._pending))
        self.press(f"cx:{token}")
        self.assertIn("отменено", self.api.texts("editMessageText")[-1])
        self.assertEqual(self.docker.calls, [])

    # -- misc ------------------------------------------------------------------------------

    def test_entities_to_html(self):
        text = "⚠️ Новое устройство\nIP: 1.2.3.4 <x>"
        entities = [{"type": "bold", "offset": 3, "length": 16}, {"type": "code", "offset": 24, "length": 7}]
        self.assertEqual(entities_to_html(text, entities), "⚠️ <b>Новое устройство</b>\nIP: <code>1.2.3.4</code> &lt;x&gt;")

    def test_health_marker(self):
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


class DowntimeReportTest(unittest.TestCase):
    def make_agent(self, storage):
        cfg = make_config(docker={"enabled": False}, lan={"enabled": False}, ssh={"enabled": False},
                          firewall={"enabled": False}, connectivity={"enabled": False})
        return Agent(cfg, api=FakeAPI(), storage=storage)  # type: ignore[arg-type]

    def test_power_loss_detected(self):
        storage = Storage(":memory:")
        agent = self.make_agent(storage)
        storage.kv_set("agent.boot_id", "old-boot")
        storage.kv_set("agent.last_alive", str(time.time() - 3600))
        with mock.patch.object(agent.system, "uptime", return_value=600):
            event = agent._downtime_report()
        self.assertEqual(event.severity, "critical")
        self.assertIn("питание", event.body)
        self.assertAlmostEqual(event.data["down_for"], 3000, delta=5)

    def test_clean_reboot(self):
        storage = Storage(":memory:")
        agent = self.make_agent(storage)
        storage.kv_set("agent.boot_id", "old-boot")
        storage.kv_set("agent.last_alive", str(time.time() - 3600))
        storage.kv_set("agent.clean_stop", str(time.time() - 3500))
        with mock.patch.object(agent.system, "uptime", return_value=600):
            event = agent._downtime_report()
        self.assertEqual(event.title, "Сервер был перезагружен")

    def test_agent_crash_same_boot(self):
        storage = Storage(":memory:")
        agent = self.make_agent(storage)
        storage.kv_set("agent.boot_id", agent.boot_id)
        storage.kv_set("agent.last_alive", str(time.time() - 900))
        event = agent._downtime_report()
        self.assertEqual(event.kind, "agent_crashed")
        storage.kv_set("agent.clean_stop", str(time.time()))
        self.assertIsNone(agent._downtime_report())


if __name__ == "__main__":
    unittest.main()
