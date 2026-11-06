# -*- coding: utf-8 -*-
"""Zhanlu native egress (Python 3.9 standard library only).

Import auth_zhanlu.json with its 32-byte .zhanlu-auth.key; authenticate the GCM
ciphertext before accepting any account. The source master key is never saved.
Imported API credentials are re-encrypted under a local, owner-only store key.
"""
import base64
import hashlib
import json
import math
import os
import secrets
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import wb_atrest
import wb_settings

DEFAULT_BASE_URL = "https://ecloud.10086.cn/api/query/aigateway"
DEFAULTS = {"enabled": False, "timeout_seconds": 30.0,
            "stream_timeout_seconds": 600.0, "models_ttl_seconds": 300.0,
            "max_concurrent": 1}
MAX_AUTH_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class ZhanluError(RuntimeError):
    def __init__(self, message, status=502):
        super().__init__(message)
        self.status = status


def _b64(value, field, size=None):
    try:
        if not isinstance(value, str) or not value:
            raise ValueError()
        raw = base64.b64decode(value, validate=True)
        if size is not None and len(raw) != size:
            raise ValueError()
        return raw
    except (ValueError, TypeError):
        raise ZhanluError("Invalid Zhanlu credential field: " + field, 400) from None


def _base_url(value):
    raw = value.strip() if isinstance(value, str) and value.strip() else DEFAULT_BASE_URL
    try:
        url = urllib.parse.urlsplit(raw)
        if (url.scheme not in ("http", "https") or not url.hostname
                or url.username or url.password or url.query or url.fragment
                or any(c.isspace() or ord(c) < 32 for c in raw)):
            raise ValueError()
        url.port
    except ValueError:
        raise ZhanluError("Invalid Zhanlu model base URL", 400) from None
    return raw.rstrip("/")


def decode_auth(document, master_key):
    """Validate and decrypt every entry before import (all-or-nothing validation)."""
    if not isinstance(master_key, bytes) or len(master_key) != 32 or not any(master_key):
        raise ZhanluError("Invalid .zhanlu-auth.key (expected 32 binary bytes)", 400)
    accounts = document.get("accounts") if isinstance(document, dict) else None
    if not isinstance(accounts, dict) or not accounts or len(accounts) > 100:
        raise ZhanluError("Invalid auth_zhanlu.json accounts", 400)
    rows = []
    for name, account in accounts.items():
        if not isinstance(name, str) or not name.strip() or len(name) > 200:
            raise ZhanluError("Invalid Zhanlu account name", 400)
        if not isinstance(account, dict) or account.get("type") != "api":
            raise ZhanluError("Zhanlu account must contain an API credential", 400)
        meta = account.get("metadata")
        if not isinstance(meta, dict) or meta.get("cipherVersion") != "zhanlu-auth-v1":
            raise ZhanluError("Unsupported Zhanlu credential cipher version", 400)
        ct = _b64(account.get("key"), "key")
        if len(ct) > 16384:
            raise ZhanluError("Zhanlu credential is too large", 400)
        iv = _b64(meta.get("iv"), "iv", 12)
        tag = _b64(meta.get("tag"), "tag", 16)
        try:
            key = wb_atrest._gcm_open(master_key, iv, b"", ct, tag).decode("utf-8").strip()
        except (wb_atrest.AtRestError, UnicodeError):
            raise ZhanluError("Zhanlu decryption failed: wrong key or tampered file", 400) from None
        if not key or any(ord(c) < 32 or ord(c) == 127 for c in key):
            raise ZhanluError("Invalid decrypted Zhanlu API credential", 400)
        base = _base_url(meta.get("modelBaseUrl") or meta.get("mobileModelBaseUrl"))
        uid = "zhanlu-" + hashlib.sha256((base + "\0" + key).encode("utf-8")).hexdigest()[:24]
        rows.append({"uid": uid, "name": name, "base_url": base, "api_key": key})
    return rows


def load_config(accounts_dir):
    raw = wb_settings.load(accounts_dir).get("zhanlu") or {}
    out = dict(DEFAULTS)
    if isinstance(raw, dict):
        out.update({k: raw[k] for k in DEFAULTS if k in raw})
    out["enabled"] = out.get("enabled") is True
    out["accounts_dir"] = accounts_dir
    return out


def save_config(accounts_dir, patch):
    if not isinstance(patch, dict):
        raise ZhanluError("zhanlu must be an object", 400)
    with wb_settings._lock:
        cfg = load_config(accounts_dir)
        for k, v in patch.items():
            if k not in DEFAULTS:
                continue
            if k == "enabled":
                if not isinstance(v, bool):
                    raise ZhanluError("zhanlu.enabled must be boolean", 400)
            else:
                if isinstance(v, bool):
                    raise ZhanluError("Invalid zhanlu setting: " + k, 400)
                try:
                    v = float(v)
                    cap = 20 if k == "max_concurrent" else 3600
                    if not math.isfinite(v) or not 1 <= v <= cap:
                        raise ValueError()
                    if k == "max_concurrent":
                        if not v.is_integer():
                            raise ValueError()
                        v = int(v)
                except (TypeError, ValueError):
                    raise ZhanluError("Invalid zhanlu setting: " + k, 400) from None
            cfg[k] = v
        data = wb_settings.load(accounts_dir)
        data["zhanlu"] = {k: cfg[k] for k in DEFAULTS}
        wb_settings.save(accounts_dir, data)
    return masked_config(accounts_dir)


def _write_private(path, payload):
    """Unique 0600 staging file and atomic replace; no plaintext secrets."""
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".zhanlu-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class Account:
    realm = product = "zhanlu"
    proxy = ""
    proxy_slot = ""
    chat_path = "/chat/completions"

    def __init__(self, row, pool):
        self.row = row
        self.pool = pool
        self.uid = row["uid"]
        self.name = self.nickname = row["name"]
        self.active_concurrent = 0
        self.cool_until = 0.0
        self.last_error = ""
        self.metadata_lock = threading.RLock()
        self.models = []
        self.models_at = 0.0
        self.credits = None

    def chat_base_url(self):
        return self.row["base_url"]

    def api_key(self):
        try:
            if not wb_atrest.is_envelope(self.row["credential"]):
                raise wb_atrest.AtRestError("Invalid envelope")
            return wb_atrest.decrypt_field(self.pool.store_key(), self.row["credential"])
        except (wb_atrest.AtRestError, KeyError):
            raise ZhanluError("Zhanlu stored credential cannot be decrypted") from None

    def view(self):
        return {"uid": self.uid, "name": self.name, "nickname": self.nickname,
                "realm": "zhanlu", "enabled": not self.row.get("disabled", False),
                "disabled": bool(self.row.get("disabled")),
                "cooling": time.time() < self.cool_until,
                "active_concurrent": self.active_concurrent,
                "base_url": self.chat_base_url(), "credits": self.credits,
                "models": len(self.models), "last_error": self.last_error}


class Pool:
    def __init__(self, accounts_dir):
        self.accounts_dir = accounts_dir
        self.folder = os.path.join(accounts_dir, "zhanlu")
        self.path = os.path.join(self.folder, "accounts.json")
        self.lock = threading.RLock()
        self.accounts = []
        self.sessions = {}
        self.cursor = 0
        try:
            with open(self.path, encoding="utf-8") as fh:
                rows = json.load(fh)
            if not isinstance(rows, list):
                raise ValueError()
            self.accounts = [Account(r, self) for r in rows
                             if isinstance(r, dict) and r.get("uid") and r.get("credential")]
        except FileNotFoundError:
            pass
        except (OSError, ValueError, KeyError):
            raise ZhanluError("Zhanlu account store cannot be read") from None

    def store_key(self, create=False):
        path = os.path.join(self.folder, ".store-key")
        try:
            if create and not os.path.exists(path):
                if self.accounts:
                    raise ZhanluError("Zhanlu local store key is missing; restore it before importing")
                os.makedirs(self.folder, mode=0o700, exist_ok=True)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(secrets.token_bytes(32))
            with open(path, "rb") as fh:
                key = fh.read(33)
            if len(key) != 32:
                raise ValueError()
            return key
        except (OSError, ValueError):
            raise ZhanluError("Zhanlu local store key is missing or unreadable") from None

    def save(self):
        _write_private(self.path, [a.row for a in self.accounts])

    def import_auth(self, document, master_key, overwrite=False):
        rows = decode_auth(document, master_key)
        with self.lock:
            local_key = self.store_key(create=True)
            accounts = list(self.accounts)
            added = updated = skipped = 0
            for row in rows:
                old = next((a for a in accounts if a.uid == row["uid"]), None)
                if old is None and overwrite:
                    matches = [a for a in accounts if a.name == row["name"]
                               and a.chat_base_url() == row["base_url"]]
                    if len(matches) > 1:
                        raise ZhanluError("Multiple matching Zhanlu accounts; remove the expired account and import without overwrite", 409)
                    old = matches[0] if matches else None
                if old and not overwrite:
                    skipped += 1
                    continue
                stored = {k: v for k, v in row.items() if k != "api_key"}
                if old:
                    stored["uid"] = old.uid  # Preserve API-key account bindings after credential renewal.
                stored["credential"] = wb_atrest.seal(local_key, row["api_key"], "field")
                stored["disabled"] = bool(old and old.row.get("disabled"))
                account = Account(stored, self)
                if old:
                    accounts[accounts.index(old)] = account
                    updated += 1
                else:
                    accounts.append(account)
                    added += 1
            _write_private(self.path, [a.row for a in accounts])
            for index, account in enumerate(accounts):
                old = next((a for a in self.accounts if a.uid == account.uid), None)
                if old and old is not account:
                    old.row = account.row
                    old.models = []
                    old.models_at = 0
                    old.cool_until = 0
                    old.last_error = ""
                    accounts[index] = old
            self.accounts = accounts
        return {"ok": True, "added": added, "updated": updated, "skipped": skipped}

    def change(self, action, uid):
        with self.lock:
            account = next((a for a in self.accounts if a.uid == uid), None)
            if account is None:
                raise ZhanluError("Zhanlu account not found", 404)
            if action == "delete":
                rows = [a for a in self.accounts if a is not account]
                _write_private(self.path, [a.row for a in rows])
                self.accounts = rows
            else:
                if action in ("enable", "disable"):
                    account.row["disabled"] = action == "disable"
                    self.save()
                account.cool_until = 0
                account.last_error = ""
            self.sessions = {k: v for k, v in self.sessions.items() if v != uid}
        return {"ok": True}

    def acquire(self, cfg, session_key=None, allowed_accounts=None, exclude=()):
        with self.lock:
            allowed = None if allowed_accounts is None else set(allowed_accounts)
            candidates = [a for a in self.accounts if not a.row.get("disabled")
                          and a.cool_until <= time.time() and a.uid not in exclude
                          and (allowed is None or a.uid in allowed)
                          and a.active_concurrent < cfg["max_concurrent"]]
            if not candidates:
                raise ZhanluError("No available Zhanlu account (disabled, cooling, busy or restricted)", 429)
            pinned = self.sessions.get(session_key)
            account = next((a for a in candidates if a.uid == pinned), None)
            if account is None:
                account = candidates[self.cursor % len(candidates)]
                self.cursor += 1
            account.active_concurrent += 1
            if session_key:
                if len(self.sessions) >= 4096:
                    self.sessions.clear()
                self.sessions[session_key] = account.uid
            return account

    def release(self, account):
        with self.lock:
            account.active_concurrent = max(0, account.active_concurrent - 1)


_POOLS = {}
_POOL_LOCK = threading.RLock()


def pool_for(accounts_dir):
    with _POOL_LOCK:
        key = os.path.realpath(accounts_dir)
        if key not in _POOLS:
            _POOLS[key] = Pool(accounts_dir)
        return _POOLS[key]


def configured(accounts_dir):
    return load_config(accounts_dir)["enabled"]


def masked_config(accounts_dir):
    cfg = load_config(accounts_dir)
    cfg.pop("accounts_dir", None)
    cfg["configured"] = cfg["enabled"]
    cfg["accounts"] = len(pool_for(accounts_dir).accounts)
    return cfg


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward a Bearer credential to a redirected origin.


def _request(account, path, timeout, body=None):
    headers = {"Authorization": "Bearer " + account.api_key(),
               "Accept": "text/event-stream" if body else "application/json",
               "User-Agent": "wb-hub/zhanlu"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(account.chat_base_url() + path, data=data, headers=headers)
    try:
        return urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        # Upstream bodies may echo credentials; do not log or return their contents.
        raise ZhanluError("Zhanlu upstream returned HTTP %d" % status,
                          status if status in (400, 401, 403, 404, 429) else 502) from None
    except (OSError, urllib.error.URLError, ValueError):
        raise ZhanluError("Zhanlu upstream is unreachable", 502) from None


def _json_response(raw):
    try:
        data = raw.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise ValueError()
        return json.loads(data)
    except (ValueError, OSError):
        raise ZhanluError("Invalid Zhanlu upstream JSON response") from None


def fetch_models(account, cfg, force=False):
    with account.metadata_lock:
        if account.models_at and not force and time.time() - account.models_at < cfg["models_ttl_seconds"]:
            return account.models
        with _request(account, "/gateway/v1/model/info", cfg["timeout_seconds"]) as raw:
            payload = _json_response(raw)
        rows = payload.get("data") if isinstance(payload, dict) else payload
        if not isinstance(rows, list):
            raise ZhanluError("Invalid Zhanlu model list")
        ids = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            info = row.get("model_info")
            mid = row.get("model_name") or row.get("id") or (info.get("id") if isinstance(info, dict) else None)
            if isinstance(mid, str) and mid.strip():
                ids.add(mid.strip())
        account.models = [{"id": mid, "object": "model", "created": 0,
                           "owned_by": "zhanlu"} for mid in sorted(ids)]
        account.models_at = time.time()
        return account.models


def model_entries(accounts_dir, allowed_accounts=None, force=False):
    cfg = load_config(accounts_dir)
    if not cfg["enabled"]:
        raise ZhanluError("Zhanlu egress is disabled", 400)
    rows = {}
    error = None
    for a in list(pool_for(accounts_dir).accounts):
        if a.row.get("disabled") or (allowed_accounts is not None and a.uid not in allowed_accounts):
            continue
        try:
            models = fetch_models(a, cfg, force)
        except ZhanluError as exc:
            error = exc
            models = a.models
        rows.update({r["id"]: r for r in models})
    if not rows and error:
        raise error
    return list(rows.values())


def fetch_credits(account, cfg):
    with _request(account, "/gateway/api/v1/external-ide/budget-info", cfg["timeout_seconds"]) as raw:
        payload = _json_response(raw)
    data = payload.get("data") if isinstance(payload, dict) and payload.get("code") == 200 else None
    if not isinstance(data, dict):
        raise ZhanluError("Invalid Zhanlu budget response")
    for k in ("max_budget", "spend", "remaining_budget"):
        v = data.get(k)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
            raise ZhanluError("Invalid Zhanlu budget field: " + k)
    account.credits = {"amount": data["max_budget"], "used": data["spend"],
                       "remain": data["remaining_budget"], "unit": "credit",
                       "updated_at": time.time()}
    return account.credits


def overview(accounts_dir):
    accounts = [a.view() for a in list(pool_for(accounts_dir).accounts)]
    return {"provider": "zhanlu", "configured": configured(accounts_dir),
            "accounts": accounts, "stats": {"total": len(accounts),
            "healthy": sum(a["enabled"] and not a["cooling"] for a in accounts)}}


class Stream:
    """Normalize SSE frames and release the account exactly once on every path."""
    def __init__(self, raw, account, model):
        self.raw, self.account, self.model = raw, account, model
        self._wb_billed_model = model
        self.closed = False
        self.pending = []
        if "text/event-stream" not in raw.headers.get("Content-Type", ""):
            payload = _json_response(raw)
            if not isinstance(payload, dict) or not isinstance(payload.get("choices"), list):
                raise ZhanluError("Invalid Zhanlu chat response")
            choices = []
            for choice in payload["choices"]:
                delta = dict(choice.get("message") or {})
                for idx, call in enumerate(delta.get("tool_calls") or []):
                    call["index"] = idx
                choices.append({"index": choice.get("index", 0), "delta": delta,
                                "finish_reason": choice.get("finish_reason")})
            chunk = {"model": model, "choices": choices, "usage": payload.get("usage")}
            self.pending = [self._frame(chunk), b"data: [DONE]\n\n"]
        else:
            frame = self._read_frame()
            if frame is None:
                raise ZhanluError("Empty Zhanlu upstream stream")
            self.pending = [frame]

    @staticmethod
    def _frame(payload):
        if not isinstance(payload, dict) or payload.get("error"):
            raise ZhanluError("Zhanlu upstream returned a stream error")
        return b"data: " + json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n\n"

    def _read_frame(self):
        data = []
        size = 0
        while True:
            line = self.raw.readline(MAX_RESPONSE_BYTES + 1)
            size += len(line)
            if size > MAX_RESPONSE_BYTES:
                raise ZhanluError("Zhanlu upstream frame is too large")
            if line.startswith(b"data:"):
                data.append(line[5:].strip())
            if (not line or not line.strip()) and data:
                text = b"\n".join(data)
                if text == b"[DONE]":
                    return b"data: [DONE]\n\n"
                try:
                    return self._frame(json.loads(text))
                except ValueError:
                    raise ZhanluError("Invalid Zhanlu upstream stream") from None
            if not line:
                return None

    def __iter__(self):
        while self.pending:
            frame = self.pending.pop(0)
            yield frame
            if frame.startswith(b"data: [DONE]"):
                return
        while not self.closed:
            try:
                frame = self._read_frame()
            except (OSError, ValueError):
                raise ZhanluError("Zhanlu upstream stream interrupted") from None
            if frame is None:
                raise ZhanluError("Zhanlu upstream stream ended before [DONE]")
            yield frame
            if frame.startswith(b"data: [DONE]"):
                return

    def close(self):
        if not self.closed:
            self.closed = True
            try:
                self.raw.close()
            finally:
                self.account.pool.release(self.account)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def open_chat(accounts_dir, payload, session_key=None, allowed_accounts=None):
    cfg = load_config(accounts_dir)
    if not cfg["enabled"]:
        raise ZhanluError("Zhanlu egress is disabled", 400)
    if not isinstance(payload.get("model"), str) or not payload["model"].strip():
        raise ZhanluError("Zhanlu requires a model from /v1/models", 400)
    body = {k: payload[k] for k in ("model", "messages", "tools", "tool_choice", "temperature",
            "top_p", "max_tokens", "max_completion_tokens", "stop", "presence_penalty",
            "frequency_penalty", "seed", "response_format", "parallel_tool_calls",
            "reasoning_effort") if k in payload}
    body["stream"] = True
    body["stream_options"] = {"include_usage": True}
    pool = pool_for(accounts_dir)
    excluded = set()
    last_error = None
    for _ in range(max(1, len(pool.accounts))):
        try:
            account = pool.acquire(cfg, session_key, allowed_accounts, excluded)
        except ZhanluError:
            if last_error:
                raise last_error
            raise
        raw = None
        try:
            raw = _request(account, "/chat/completions", cfg["stream_timeout_seconds"], body)
            stream = Stream(raw, account, body["model"])
            account.last_error = ""
            return stream, account, body.get("reasoning_effort")
        except ZhanluError as exc:
            last_error = exc
            account.last_error = str(exc)
            if exc.status != 400:
                account.cool_until = time.time() + (300 if exc.status in (401, 403) else 60)
            if raw:
                raw.close()
            pool.release(account)
            if exc.status == 400:
                raise
            excluded.add(account.uid)
        except Exception:
            if raw:
                raw.close()
            pool.release(account)
            raise ZhanluError("Invalid Zhanlu chat response") from None
    raise last_error or ZhanluError("No available Zhanlu account", 429)
