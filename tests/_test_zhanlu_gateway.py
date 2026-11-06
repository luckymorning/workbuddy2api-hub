"""Fake Zhanlu upstream + real hub: panel import, three protocols and attribution."""
import base64
import copy
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from _isolated_dirs import isolated_data_dirs
_TMP = isolated_data_dirs("wb-zhanlu-gateway-")
ACCOUNTS = os.environ["ACCOUNTS_DIR"]
import wb_proxy as P
import wb_settings as S
import wb_zhanlu as Z
from _test_zhanlu import AUTH, MASTER


class Upstream(BaseHTTPRequestHandler):
    requests = []
    mode = "sse"
    def log_message(self, *args):
        pass

    def send_json(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.assert_auth()
        if self.path.endswith("/gateway/v1/model/info"):
            self.send_json(200, {"data": [{"model_name": "test-model"}, {"id": "test-model"},
                                        {"model_info": {"id": "tool-model"}}]})
        elif self.path.endswith("/budget-info"):
            self.send_json(200, {"code": 200, "data": {
                "max_budget": 500, "spend": 12.5, "remaining_budget": 487.5}})
        else:
            self.send_json(404, {})

    def assert_auth(self):
        assert self.headers.get("Authorization") in ("Bearer fixture-api-key", "Bearer fixture-api-key-two")

    def do_POST(self):
        self.assert_auth()
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.requests.append(body)
        assert self.path.endswith("/chat/completions")
        assert body["stream"] is True
        if self.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/credential-sink")
            self.end_headers()
            return
        if self.mode == "error":
            self.send_json(401, {"error": "fixture-api-key"})
            return
        if self.mode == "json":
            self.send_json(200, {"choices": [{"message": {"role": "assistant", "content": "hello zhanlu"},
                                           "finish_reason": "stop"}],
                                 "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}})
            return
        delta = {"role": "assistant", "content": "hello zhanlu", "reasoning_content": "thinking"}
        finish = "stop"
        if body.get("tools"):
            tool = body["tools"][0]["function"]["name"]
            delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": "call_fixture",
                     "type": "function", "function": {"name": tool, "arguments": '{"city":"Shanghai"}'}}]}
            finish = "tool_calls"
        chunk = {"id": "chatcmpl-fixture", "model": body["model"], "choices": [{
            "index": 0, "delta": delta, "finish_reason": finish}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}}
        data = ("data: " + json.dumps(chunk) + "\r\n\r\ndata: [DONE]\r\n\r\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class NoWorkBuddyPool:
    accounts = []
    def get(self, uid):
        return None
    def __getattr__(self, name):
        raise AssertionError("Zhanlu incorrectly used WorkBuddy pool: " + name)


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()
        cls.hub = P.GatewayServer(("127.0.0.1", 0), P.Handler)
        threading.Thread(target=cls.hub.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d" % cls.hub.server_address[1]
        P.POOL = NoWorkBuddyPool()
        P.API_KEY = None
        P.CURRENT_REALM = "intl"
        cls.pool = Z.pool_for(ACCOUNTS)
        cls.auth = copy.deepcopy(AUTH)
        cls.auth["accounts"]["ecloud"]["metadata"]["modelBaseUrl"] = (
            "http://127.0.0.1:%d/api/query/aigateway" % cls.upstream.server_address[1])
        status, body = cls.call("POST", "/panel/login", {"password": "admin"})
        assert status == 200
        cls.token = json.loads(body)["token"]
        status, body = cls.call("POST", "/zhanlu/accounts/import", {
            "auth": cls.auth, "master_key": base64.b64encode(MASTER).decode()}, panel=True)
        assert status == 200, body
        cls.uid = cls.pool.accounts[0].uid
        Z.save_config(ACCOUNTS, {"enabled": True})
        S.set_enable_anthropic_messages(ACCOUNTS, True)
        S.set_api_keys(ACCOUNTS, [{"key": "hub-zhanlu-fixture", "realm": "zhanlu", "accounts": [cls.uid]}])
        cls.key_id = S.api_keys(ACCOUNTS)[0]["id"]

    @classmethod
    def tearDownClass(cls):
        cls.hub.shutdown()
        cls.hub.server_close()
        cls.upstream.shutdown()
        cls.upstream.server_close()

    @classmethod
    def call(cls, method, path, payload=None, panel=False, api=False):
        headers = {"Content-Type": "application/json"}
        if panel:
            headers["X-Panel-Token"] = cls.token
        if api:
            headers["Authorization"] = "Bearer hub-zhanlu-fixture"
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(cls.url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read().decode()

    def setUp(self):
        Z.save_config(ACCOUNTS, {"enabled": True})
        Upstream.mode = "sse"
        for a in self.pool.accounts:
            a.cool_until = 0
            a.row["disabled"] = False

    def test_admin_auth_and_no_leak(self):
        for path in ("/zhanlu/accounts", "/zhanlu/overview"):
            self.assertEqual(self.call("GET", path, api=True)[0], 401)
        self.assertEqual(self.call("POST", "/zhanlu/accounts/import", {}, api=True)[0], 401)
        status, raw = self.call("GET", "/zhanlu/overview", panel=True)
        self.assertEqual(status, 200)
        for secret in ("fixture-api-key", base64.b64encode(MASTER).decode(), "master_key", "credential"):
            self.assertNotIn(secret, raw)
        status, raw = self.call("POST", "/zhanlu/accounts/import", {
            "auth": self.auth, "master_key": "bad"}, panel=True)
        self.assertEqual(status, 400)

    def test_models_and_budget(self):
        status, raw = self.call("GET", "/v1/models?realm=cn", api=True)
        self.assertEqual(status, 200)  # Key binding has precedence over query.
        models = json.loads(raw)
        self.assertEqual(models["realm"], "zhanlu")
        self.assertEqual({m["id"] for m in models["data"]}, {"test-model", "tool-model"})
        status, raw = self.call("POST", "/zhanlu/accounts/credits", {"uid": self.uid}, panel=True)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["results"][0]["credits"]["remain"], 487.5)
        status, raw = self.call("GET", "/v1/balance-summary", api=True)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["balance"], 487.5)

    def test_protocols(self):
        requests = {
            "/v1/chat/completions": {"model": "test-model", "messages": [{"role": "user", "content": "hi"}]},
            "/v1/responses": {"model": "test-model", "input": "hi"},
            "/v1/messages": {"model": "test-model", "max_tokens": 64,
                             "messages": [{"role": "user", "content": "hi"}]},
        }
        for path, body in requests.items():
            for stream in (False, True):
                with self.subTest(path=path, stream=stream):
                    status, raw = self.call("POST", path, dict(body, stream=stream), api=True)
                    self.assertEqual(status, 200, raw)
                    self.assertIn("hello zhanlu", raw)
                    if stream:
                        self.assertIn({"/v1/chat/completions": "[DONE]", "/v1/responses": "response.completed",
                                       "/v1/messages": "message_stop"}[path], raw)
                    self.assertEqual(self.pool.accounts[0].active_concurrent, 0)
        rows = [r for r in P.recent_usage(100, realm="zhanlu")["rows"] if r.get("outcome") == "completed"]
        self.assertGreaterEqual(len(rows), 6)
        self.assertTrue(all(row["account"] == self.uid and row["key"] == self.key_id for row in rows))
        self.assertTrue(all(row["cost_policy"] == "zhanlu:unpriced" for row in rows))
        self.assertTrue(all(row["total_tokens"] == 5 for row in rows))

    def test_namespace_tool_and_image_forwarding(self):
        body = {"model": "tool-model", "input": [{"role": "user", "content": [
            {"type": "input_text", "text": "hi"},
            {"type": "input_image", "image_url": "data:image/png;base64,AA=="}]}],
            "tools": [{"type": "namespace", "name": "weather", "tools": [
                {"type": "function", "name": "forecast", "parameters": {"type": "object"}}]}]}
        status, raw = self.call("POST", "/v1/responses", body, api=True)
        self.assertEqual(status, 200, raw)
        self.assertIn('"namespace": "weather"', raw)
        self.assertIn("data:image/png;base64,AA==", json.dumps(Upstream.requests[-1]))

    def test_json_fallback_and_redacted_upstream_errors(self):
        body = {"model": "test-model", "messages": [{"role": "user", "content": "hi"}]}
        Upstream.mode = "json"
        status, raw = self.call("POST", "/v1/chat/completions", body, api=True)
        self.assertEqual(status, 200, raw)
        self.assertIn("hello zhanlu", raw)
        for mode in ("error", "redirect"):
            self.pool.accounts[0].cool_until = 0
            Upstream.mode = mode
            status, raw = self.call("POST", "/v1/chat/completions", body, api=True)
            self.assertGreaterEqual(status, 400)
            self.assertNotIn("fixture-api-key", raw)
            self.assertEqual(self.pool.accounts[0].active_concurrent, 0)

    def test_account_failover_and_allowlist(self):
        import unittest.mock
        duplicate = copy.deepcopy(self.auth)
        duplicate["accounts"]["second"] = duplicate["accounts"].pop("ecloud")
        duplicate["accounts"]["second"]["key"] = "IWuub7CXpzbsMf6m2owBQPeh6A=="
        duplicate["accounts"]["second"]["metadata"]["tag"] = "PEXZ0tsCJo+tkpKZxKQFkw=="
        self.pool.import_auth(duplicate, MASTER)
        original = Z._request
        def fail_first(account, *args, **kwargs):
            if account.uid == self.uid:
                raise Z.ZhanluError("Zhanlu upstream returned HTTP 401", 401)
            return original(account, *args, **kwargs)
        body = {"model": "test-model", "messages": [{"role": "user", "content": "hi"}]}
        try:
            with unittest.mock.patch.object(Z, "_request", side_effect=fail_first):
                stream, account, _ = Z.open_chat(ACCOUNTS, body, "failover")
                with stream:
                    self.assertIn(b"hello zhanlu", b"".join(stream))
                self.assertNotEqual(account.uid, self.uid)
                self.pool.accounts[0].cool_until = 0
                with self.assertRaises(Z.ZhanluError):
                    Z.open_chat(ACCOUNTS, body, allowed_accounts=[self.uid])
        finally:
            self.pool.change("delete", self.pool.accounts[-1].uid)

    def test_key_restriction_and_default_realm(self):
        self.assertIn("zhanlu", P.realm_options())
        status, raw = self.call("POST", "/realm", {"realm": "zhanlu"}, panel=True)
        self.assertEqual(status, 200, raw)
        P.CURRENT_REALM = "intl"
        self.assertEqual(P.load_persisted_realm(), "zhanlu")
        Z.save_config(ACCOUNTS, {"enabled": False})
        self.assertNotIn("zhanlu", P.realm_options())
        self.assertEqual(self.call("POST", "/realm", {"realm": "zhanlu"}, panel=True)[0], 400)
        status, raw = self.call("POST", "/settings/save", {"zhanlu": {"enabled": False}}, panel=True)
        self.assertEqual(status, 200, raw)
        self.assertEqual(P.CURRENT_REALM, "intl")
        Z.save_config(ACCOUNTS, {"enabled": True})


if __name__ == "__main__":
    unittest.main()
