import os
import tempfile
import unittest

from shelter_monitor.agent import config as config_mod
from tests.helpers import TOKEN, make_config


class ConfigTest(unittest.TestCase):
    def test_minimal_config_has_defaults(self):
        cfg = make_config()
        self.assertEqual(cfg.telegram.admin_ids, [111])
        self.assertEqual(cfg.notify_chats, [111])
        self.assertEqual(cfg.monitor.interval, 30)
        self.assertIn("ssh", cfg.services.units)
        self.assertFalse(cfg.heartbeat.enabled)

    def test_missing_token_and_admins(self):
        with self.assertRaises(config_mod.ConfigError) as ctx:
            config_mod.from_dict({"telegram": {}})
        self.assertIn("token", str(ctx.exception))
        self.assertIn("admin_ids", str(ctx.exception))

    def test_type_errors(self):
        with self.assertRaises(config_mod.ConfigError):
            make_config(monitor={"interval": "30"})
        with self.assertRaises(config_mod.ConfigError):
            make_config(docker={"enabled": "yes"})

    def test_unknown_keys_are_warnings(self):
        cfg = make_config(monitor={"bogus": 1})
        self.assertTrue(any("bogus" in w for w in cfg.warnings))

    def test_rejects_dangerous_names(self):
        for bad in ["nginx; rm -rf /", "-evil", "a b", "../x"]:
            with self.assertRaises(config_mod.ConfigError, msg=bad):
                make_config(actions={"services": [bad]})
        with self.assertRaises(config_mod.ConfigError):
            make_config(actions={"containers": ["$(id)"]})

    def test_heartbeat_validation(self):
        with self.assertRaises(config_mod.ConfigError):
            make_config(heartbeat={"enabled": True, "url": "ftp://x"})
        cfg = make_config(heartbeat={"enabled": True, "url": "http://wd.local/api/v1/heartbeat", "method": "get"})
        self.assertEqual(cfg.heartbeat.method, "GET")
        self.assertTrue(any("plain http" in w for w in cfg.warnings))

    def test_invalid_networks(self):
        with self.assertRaises(config_mod.ConfigError):
            make_config(ssh={"trusted_networks": ["not-a-net"]})
        with self.assertRaises(config_mod.ConfigError):
            make_config(lan={"subnets": ["fe80::/64"]})

    def test_token_from_file_and_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "token")
            with open(path, "w") as fh:
                fh.write(TOKEN + "\n")
            cfg = config_mod.from_dict({"telegram": {"token_file": path, "admin_ids": [1]}})
            self.assertEqual(cfg.telegram.token, TOKEN)

    def test_load_example_config(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        raw = config_mod.load_toml(os.path.join(root, "config", "agent.example.toml"))
        raw["telegram"]["token"] = TOKEN
        raw["telegram"]["admin_ids"] = [42]
        cfg = config_mod.from_dict(raw)
        self.assertEqual(cfg.warnings, [])

    def test_normalize_unit(self):
        self.assertEqual(config_mod.normalize_unit("nginx"), "nginx.service")
        self.assertEqual(config_mod.normalize_unit("backup.timer"), "backup.timer")
        self.assertEqual(config_mod.normalize_unit("php8.2-fpm"), "php8.2-fpm.service")

    def test_masked_dump(self):
        dumped = config_mod.as_dict(make_config())
        self.assertEqual(dumped["telegram"]["token"], "***")


if __name__ == "__main__":
    unittest.main()
