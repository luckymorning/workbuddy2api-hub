"""Zhanlu encrypted-file import, secure persistence and pool invariants."""
import base64
import copy
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import wb_atrest
import wb_zhanlu as Z

# Synthetic Node crypto AES-256-GCM vector, not a real credential.
MASTER = bytes(range(32))
AUTH = {"accounts": {"ecloud": {"type": "api", "key": "IWuub7CXpzbsMf6m2owB",
        "metadata": {"cipherVersion": "zhanlu-auth-v1", "iv": "AAECAwQFBgcICQoL",
                     "tag": "wDlBCYHD45dPIUZjjtCsOQ=="}}}}


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="wb-zhanlu-unit-")
        self.addCleanup(self.tmp.cleanup)
        self.pool = Z.Pool(self.tmp.name)

    def test_node_vector(self):
        row = Z.decode_auth(AUTH, MASTER)[0]
        self.assertEqual(row["api_key"], "fixture-api-key")
        self.assertEqual(row["base_url"], Z.DEFAULT_BASE_URL)

    def test_reject_wrong_key_tampering_and_headers(self):
        for master in (b"wrong", bytes(32), bytes(reversed(range(32)))):
            with self.assertRaises(Z.ZhanluError):
                self.pool.import_auth(AUTH, master)
        for field, value in (("iv", "bad"), ("tag", "bad"), ("cipherVersion", "v2"),
                             ("modelBaseUrl", "https://user:password@example.test"),
                             ("modelBaseUrl", "https://example.test?key=secret")):
            auth = copy.deepcopy(AUTH)
            auth["accounts"]["ecloud"]["metadata"][field] = value
            with self.assertRaises(Z.ZhanluError):
                self.pool.import_auth(auth, MASTER)
        self.assertEqual(self.pool.accounts, [])
        self.assertFalse(os.path.exists(self.pool.folder))

    def test_duplicate_import_and_restart_are_encrypted(self):
        self.assertEqual(self.pool.import_auth(AUTH, MASTER)["added"], 1)
        self.assertEqual(self.pool.import_auth(AUTH, MASTER)["skipped"], 1)
        self.assertEqual(self.pool.import_auth(AUTH, MASTER, True)["updated"], 1)
        with open(self.pool.path, "rb") as fh:
            saved = fh.read()
        self.assertNotIn(b"fixture-api-key", saved)
        self.assertNotIn(MASTER, saved)
        self.assertNotIn(b"api_key", saved)
        restored = Z.Pool(self.tmp.name)
        self.assertEqual(restored.accounts[0].api_key(), "fixture-api-key")
        self.assertTrue(wb_atrest.is_envelope(restored.accounts[0].row["credential"]))
        if os.name != "nt":
            self.assertEqual(os.stat(self.pool.path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(os.path.join(self.pool.folder, ".store-key")).st_mode & 0o777, 0o600)
        self.assertNotIn("fixture-api-key", json.dumps(restored.accounts[0].view()))

    def test_multi_account_validation_is_atomic(self):
        bad = copy.deepcopy(AUTH)
        bad["accounts"]["broken"] = {"type": "api"}
        with self.assertRaises(Z.ZhanluError):
            self.pool.import_auth(bad, MASTER)
        self.assertEqual(len(self.pool.accounts), 0)

    def test_pool_restriction_busy_release_and_disable(self):
        self.pool.import_auth(AUTH, MASTER)
        cfg = dict(Z.DEFAULTS)
        with self.assertRaises(Z.ZhanluError):
            self.pool.acquire(cfg, allowed_accounts=[])
        a = self.pool.acquire(cfg, "session")
        with self.assertRaises(Z.ZhanluError):
            self.pool.acquire(cfg)
        self.pool.release(a)
        self.assertIs(self.pool.acquire(cfg, "session"), a)
        self.pool.release(a)
        self.pool.change("disable", a.uid)
        self.assertTrue(Z.Pool(self.tmp.name).accounts[0].row["disabled"])
        with self.assertRaises(Z.ZhanluError):
            self.pool.acquire(cfg)
        self.pool.change("enable", a.uid)
        self.assertFalse(a.row["disabled"])
        self.pool.change("delete", a.uid)
        self.assertEqual(Z.Pool(self.tmp.name).accounts, [])

    def test_config_default_and_validation(self):
        self.assertFalse(Z.configured(self.tmp.name))
        self.assertTrue(Z.save_config(self.tmp.name, {"enabled": True})["configured"])
        for patch in ({"enabled": "true"}, {"max_concurrent": 1.5},
                      {"timeout_seconds": float("nan")}, {"max_concurrent": True}):
            with self.assertRaises(Z.ZhanluError):
                Z.save_config(self.tmp.name, patch)

    def test_no_plaintext_store_downgrade(self):
        self.pool.import_auth(AUTH, MASTER)
        self.pool.accounts[0].row["credential"] = "malicious plaintext"
        with self.assertRaises(Z.ZhanluError):
            self.pool.accounts[0].api_key()

    def test_same_provider_name_can_hold_different_accounts(self):
        self.pool.import_auth(AUTH, MASTER)
        original_uid = self.pool.accounts[0].uid
        renewed = copy.deepcopy(AUTH)
        renewed["accounts"]["ecloud"]["key"] = "IWuub7CXpzbsMf6m2owBQPeh6A=="
        renewed["accounts"]["ecloud"]["metadata"]["tag"] = "PEXZ0tsCJo+tkpKZxKQFkw=="
        self.pool.import_auth(renewed, MASTER, True)
        self.assertEqual(len(self.pool.accounts), 1)
        self.assertEqual(self.pool.accounts[0].uid, original_uid)
        self.assertEqual(self.pool.accounts[0].api_key(), "fixture-api-key-two")
        self.pool.change("delete", original_uid)
        self.pool.import_auth(AUTH, MASTER)
        self.pool.import_auth(renewed, MASTER)
        self.assertEqual(len(self.pool.accounts), 2)
        self.assertNotEqual(self.pool.accounts[0].uid, self.pool.accounts[1].uid)

    def test_reimport_preserves_inflight_account(self):
        self.pool.import_auth(AUTH, MASTER)
        a = self.pool.acquire(dict(Z.DEFAULTS))
        self.pool.import_auth(AUTH, MASTER, True)
        self.assertIs(a, self.pool.accounts[0])
        self.assertEqual(a.active_concurrent, 1)
        self.pool.release(a)
        self.assertEqual(a.active_concurrent, 0)

    def test_missing_store_key_is_not_replaced(self):
        self.pool.import_auth(AUTH, MASTER)
        os.unlink(os.path.join(self.pool.folder, ".store-key"))
        with self.assertRaises(Z.ZhanluError):
            self.pool.accounts[0].api_key()
        with self.assertRaises(Z.ZhanluError):
            self.pool.import_auth(AUTH, MASTER, True)
        self.assertFalse(os.path.exists(os.path.join(self.pool.folder, ".store-key")))

    def test_stream_error_is_redacted_and_multiline_is_supported(self):
        self.pool.import_auth(AUTH, MASTER)
        a = self.pool.acquire(dict(Z.DEFAULTS))
        class Raw(io.BytesIO):
            headers = {"Content-Type": "text/event-stream"}
        raw = Raw(b'data: {"choices": [],\r\ndata: "usage": {"total_tokens": 3}}\r\n\r\ndata: [DONE]\r\n\r\n')
        stream = Z.Stream(raw, a, "m")
        self.assertIn(b'"total_tokens": 3', list(stream)[0])
        stream.close()
        stream.close()
        self.assertEqual(a.active_concurrent, 0)
        raw = Raw(b'data: {"error": "fixture-api-key"}\n\n')
        with self.assertRaises(Z.ZhanluError) as caught:
            Z.Stream(raw, a, "m")
        self.assertNotIn("fixture-api-key", str(caught.exception))
        raw = Raw(b'data: {"choices": []}\n\n')
        stream = Z.Stream(raw, a, "m")
        with self.assertRaises(Z.ZhanluError):
            list(stream)
        stream.close()


if __name__ == "__main__":
    unittest.main()
