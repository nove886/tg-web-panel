import importlib.util
import io
import json
import os
import pathlib
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

PACKAGE = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("panel", PACKAGE / "main.py")
panel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel)


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get("PANEL_TEST_TMP"))
        self.root = pathlib.Path(self.tmp.name)
        self.config = self.root / "config.json"
        self.raw = {"domain": "tg.test.net", "listen_port": 0, "secret": "", "tls": {"mode": "self_signed"}}
        self.config.write_text(json.dumps(self.raw), encoding="utf-8")
        (self.root / "public").mkdir()
        (self.root / "public" / "index.html").write_text("hello")
        self.runtime = self.root / ".runtime"
        self.runtime.mkdir()
        self.patches = [patch.object(panel, "ROOT", self.root), patch.object(panel, "RUNTIME", self.runtime)]
        for p in self.patches:
            p.start()
        panel.STOP.clear()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def update(self, **kw):
        self.raw.update(kw)
        self.config.write_text(json.dumps(self.raw), encoding="utf-8")

    def test_panel_port_auto_detection_and_explicit_priority(self):
        self.assertEqual(panel.load_config(self.config, {"SERVER_PORT": "23456"})["listen_port"], 23456)
        self.assertEqual(panel.load_config(self.config, {"PORT": "23457"})["listen_port"], 23457)
        self.update(listen_port=12345)
        self.assertEqual(panel.load_config(self.config, {"SERVER_PORT": "23456"})["listen_port"], 12345)

    def test_missing_or_invalid_port_fails_without_prompt(self):
        with self.assertRaises(panel.SetupError):
            panel.load_config(self.config, {})
        for value in (True, -1, 65536, "abc", 1.5):
            self.update(listen_port=value)
            with self.assertRaises(panel.SetupError):
                panel.load_config(self.config, {})

    def test_domains_and_unknown_settings(self):
        for domain in ("https://tg.test.net", "tg.test.net:23456", "tg.test.net/path", "127.0.0.1", "localhost", "bad_label.test.net"):
            self.update(domain=domain, listen_port=23456)
            with self.assertRaises(panel.SetupError):
                panel.load_config(self.config, {})
        self.update(domain="tg.test.net", typo=True)
        with self.assertRaises(panel.SetupError):
            panel.load_config(self.config, {})

    def test_secret_stable_and_explicit_override(self):
        first = panel.ensure_secret({"secret": ""})
        self.assertEqual(len(first), 32)
        self.assertEqual(panel.ensure_secret({"secret": ""}), first)
        self.assertEqual(panel.ensure_secret({"secret": "a" * 32}), "a" * 32)
        self.assertEqual(panel.ensure_secret({"secret": ""}), first)

    def test_runtime_configs_isolate_private_files_and_disable_fake_tls(self):
        self.update(listen_port=23456)
        c = panel.load_config(self.config, {})
        secret = "dd" + "12" * 16
        panel.make_runtime_configs(c, secret, [11001, 11002, 11003])
        relay = panel.read_json(self.runtime / "tproxy.json")
        self.assertEqual(relay["listen"], "127.0.0.1:11002")
        self.assertEqual(relay["admin_listen"], "127.0.0.1:11003")
        self.assertEqual(pathlib.Path(relay["public_dir"]), self.root / "public")
        backend = {}
        exec((self.runtime / "backend.py").read_text(), {}, backend)
        self.assertEqual(backend["MODES"], {"classic": False, "secure": True, "tls": False})
        self.assertEqual(backend["USERS"]["panel"], "12" * 16)
        self.assertFalse(backend["USE_MIDDLE_PROXY"])
        profile = panel.read_json(self.runtime / "profiles.json")
        self.assertEqual(profile["profiles"][0]["secret"], secret)
        token = (self.runtime / "token.key").read_bytes()
        panel.make_runtime_configs(c, secret, [11004, 11005, 11006])
        self.assertEqual((self.runtime / "token.key").read_bytes(), token)
        self.assertIn("t.me/webproxy?server=tg.test.net", (self.root / "proxy-link.txt").read_text())
        self.assertFalse((self.root / "public" / "proxy-link.txt").exists())

    def test_plain_secret_starting_dd_remains_classic(self):
        self.update(listen_port=23456)
        panel.make_runtime_configs(panel.load_config(self.config, {}), "dd" + "12" * 15, [11001, 11002, 11003])
        backend = {}
        exec((self.runtime / "backend.py").read_text(), {}, backend)
        self.assertTrue(backend["MODES"]["classic"])
        self.assertFalse(backend["MODES"]["secure"])

    def test_archive_traversal_and_symlink_rejected(self):
        for name, kind in [("root/../../escape", tarfile.REGTYPE), ("root/link", tarfile.SYMTYPE)]:
            archive = self.runtime / "bad.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.linkname = "/tmp/escape"
                tar.addfile(entry, io.BytesIO())
            with self.assertRaises(panel.SetupError):
                panel.unpack(archive, self.runtime / "extract")

    def test_valid_archive_and_size_limit(self):
        archive = self.runtime / "ok.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            entry = tarfile.TarInfo("repo/nested/a.txt")
            entry.size = 4
            tar.addfile(entry, io.BytesIO(b"abcd"))
        panel.unpack(archive, self.runtime / "extract")
        self.assertEqual((self.runtime / "extract" / "nested" / "a.txt").read_bytes(), b"abcd")
        with self.assertRaises(panel.SetupError):
            panel.unpack(archive, self.runtime / "small", max_size=2)

    def test_cleanup_cannot_remove_user_directory(self):
        with self.assertRaises(panel.SetupError):
            panel.remove_runtime_tree(self.root)
        with self.assertRaises(panel.SetupError):
            panel.remove_runtime_tree(self.runtime)

    def test_secret_redaction(self):
        value = panel.ensure_secret({"secret": ""})
        self.assertNotIn(value, panel.redact("Secret: " + value))
        self.assertNotIn("secret=123", panel.redact("https://t.me/webproxy?server=x&secret=123"))

    def test_distinct_internal_ports(self):
        ports = panel.reserve_internal_ports(23456)
        self.assertEqual(len(set(ports)), 3)
        self.assertNotIn(23456, ports)

    def test_child_stop_reaps_process(self):
        child = panel.start_process("test", [sys.executable, "-c", "import time; time.sleep(60)"])
        panel.stop_process(child)
        self.assertIsNotNone(child.poll())

    def test_check_only_has_no_download_side_effects(self):
        self.update(listen_port=23456)
        result = subprocess.run([sys.executable, str(PACKAGE / "main.py"), "--config", str(self.config), "--check-config"], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.runtime / "downloads").exists())


if __name__ == "__main__":
    unittest.main()
