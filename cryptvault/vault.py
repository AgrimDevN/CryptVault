"""
Vault service: ties the crypto core, the TEVHC audit chain and SQLite storage together.

Trust split
  * "Server" side  = the SQLite database (ciphertext + metadata only).
  * "Client" side  = this process while a vault is unlocked (holds the VMK in memory)
                     plus a small per-device checkpoint file (ClientState).
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

from . import crypto_core as cc
from .audit import GENESIS, compute_mac, verify_chain
from .db import connect


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class VaultError(Exception):
    pass


class ClientState:
    """Per-device local state: device id + last-seen audit-chain head (anti-truncation checkpoint)."""

    def __init__(self, path: str):
        self.path = path
        self.data = {"device_id": f"dev-{uuid.uuid4().hex[:8]}", "checkpoints": {}}
        if os.path.exists(path):
            with open(path) as fh:
                self.data = json.load(fh)
        else:
            self._save()

    @property
    def device_id(self) -> str:
        return self.data["device_id"]

    def checkpoint(self, vault_id: str):
        return self.data["checkpoints"].get(vault_id)

    def set_checkpoint(self, vault_id: str, seq: int, head: str):
        self.data["checkpoints"][vault_id] = {"seq": seq, "head": head}
        self._save()

    def _save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w") as fh:
            json.dump(self.data, fh, indent=2)


class VaultService:
    def __init__(self, db_path: str, client_state_path: str, params: cc.KdfParams = cc.DEFAULT_PARAMS):
        self.conn = connect(db_path)
        self.client = ClientState(client_state_path)
        self.params = params

    # ------------------------------------------------------------ account
    def register(self, username: str, password: str) -> str:
        username = username.strip().lower()
        if not username or len(password) < 8:
            raise VaultError("Username required and master password must be at least 8 characters")
        if self.conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            raise VaultError("Username already exists")

        user_id, vault_id = f"usr-{uuid.uuid4().hex[:8]}", f"vault-{uuid.uuid4().hex[:8]}"
        auth_salt, kek_salt = cc.random_bytes(cc.SALT_LEN), cc.random_bytes(cc.SALT_LEN)
        auth_hash = cc.hash_auth_password(password, auth_salt, self.params)
        kek = cc.derive_kek(password, kek_salt, self.params)
        vmk = cc.random_bytes(cc.KEY_LEN)                      # random, NOT password-derived
        vmk_nonce, vmk_wrapped = cc.wrap_vmk(kek, vmk, user_id)
        ver_nonce, ver_blob = cc.make_vault_verifier(vmk, vault_id)

        self.conn.execute(
            "INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (user_id, username, auth_salt, auth_hash, kek_salt, vmk_nonce, vmk_wrapped,
             vault_id, ver_nonce, ver_blob, now()))
        self.conn.commit()
        UnlockedVault(self, user_id, vault_id, vmk)._append_event("VAULT_CREATE", None, None, None)
        return user_id

    def _user(self, username: str):
        row = self.conn.execute("SELECT * FROM users WHERE username=?",
                                (username.strip().lower(),)).fetchone()
        if not row:
            raise VaultError("Invalid username or password")
        return row

    def unlock(self, username: str, password: str) -> "UnlockedVault":
        u = self._user(username)
        # Step 1 - account login (PBKDF2 verifier, constant-time compare)
        if not cc.verify_auth_password(password, u["auth_salt"], u["auth_hash"], self.params):
            raise VaultError("Invalid username or password")
        # Step 2 - vault unlock (Argon2id -> KEK -> unwrap VMK -> check verifier)
        kek = cc.derive_kek(password, u["kek_salt"], self.params)
        vmk = cc.unwrap_vmk(kek, u["vmk_nonce"], u["vmk_wrapped"], u["user_id"])
        if not cc.check_vault_verifier(vmk, u["vault_id"], u["verifier_nonce"], u["verifier_blob"]):
            raise VaultError("Vault verifier mismatch")
        return UnlockedVault(self, u["user_id"], u["vault_id"], vmk)

    def change_master_password(self, username: str, old: str, new: str):
        """Only the VMK envelope is re-wrapped - no record is decrypted or re-encrypted."""
        if len(new) < 8:
            raise VaultError("New master password must be at least 8 characters")
        vault = self.unlock(username, old)
        auth_salt, kek_salt = cc.random_bytes(cc.SALT_LEN), cc.random_bytes(cc.SALT_LEN)
        kek = cc.derive_kek(new, kek_salt, self.params)
        vmk_nonce, vmk_wrapped = cc.wrap_vmk(kek, vault.vmk, vault.user_id)
        self.conn.execute(
            "UPDATE users SET auth_salt=?, auth_hash=?, kek_salt=?, vmk_nonce=?, vmk_wrapped=? WHERE user_id=?",
            (auth_salt, cc.hash_auth_password(new, auth_salt, self.params), kek_salt,
             vmk_nonce, vmk_wrapped, vault.user_id))
        self.conn.commit()
        vault._append_event("KEY_ROTATE", None, None, None)
        vault.lock()


class UnlockedVault:
    RECORD_FIELDS = ("title", "category", "username", "password", "url", "notes")

    def __init__(self, svc: VaultService, user_id: str, vault_id: str, vmk: bytes):
        self.svc, self.user_id, self.vault_id = svc, user_id, vault_id
        self.vmk = bytearray(vmk)
        self.device_id = svc.client.device_id

    @property
    def conn(self):
        return self.svc.conn

    def _vmk(self) -> bytes:
        if not any(self.vmk):
            raise VaultError("Vault is locked")
        return bytes(self.vmk)

    def lock(self):
        for i in range(len(self.vmk)):          # best-effort wipe of key material
            self.vmk[i] = 0

    # ------------------------------------------------------------ audit chain
    def _events(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM audit_events WHERE vault_id=? ORDER BY seq",
                                 (self.vault_id,)).fetchall()
        return [dict(r) for r in rows]

    def _append_event(self, etype, record_id, version, ct_hash):
        last = self.conn.execute(
            "SELECT seq, event_mac FROM audit_events WHERE vault_id=? ORDER BY seq DESC LIMIT 1",
            (self.vault_id,)).fetchone()
        seq, prev = (last["seq"] + 1, last["event_mac"]) if last else (1, GENESIS)
        ev = {"seq": seq, "event_type": etype, "record_id": record_id, "record_version": version,
              "ciphertext_hash": ct_hash, "timestamp": now()}
        ev["prev_mac"] = prev
        ev["event_mac"] = compute_mac(cc.audit_key(self._vmk(), self.vault_id), ev, prev)
        self.conn.execute("INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?)",
                          (self.vault_id, seq, etype, record_id, version, ct_hash,
                           ev["timestamp"], prev, ev["event_mac"]))
        self.conn.commit()
        self.svc.client.set_checkpoint(self.vault_id, seq, ev["event_mac"])

    def verify_integrity(self):
        """Replays the TEVHC from genesis and cross-checks it against stored records."""
        report = verify_chain(cc.audit_key(self._vmk(), self.vault_id), self._events())
        cp = self.svc.client.checkpoint(self.vault_id)
        if cp:
            events = self._events()
            if len(events) < cp["seq"] or events[cp["seq"] - 1]["event_mac"] != cp["head"]:
                report.valid = False
                report.problems.append(
                    f"History truncated/rolled back: device last saw seq {cp['seq']}, server has {len(events)}")
        return report

    # ------------------------------------------------------------ CRUD
    def _clean(self, entry: dict) -> dict:
        data = {k: str(entry.get(k, "") or "").strip() for k in self.RECORD_FIELDS}
        if not data["title"]:
            raise VaultError("Title is required")
        data["category"] = data["category"] or "General"
        return data

    def _store(self, record_id: str, version: int, record_type: str, data: dict, insert: bool):
        aad = cc.build_aad(self.vault_id, record_id, version, record_type, self.device_id)
        env = cc.encrypt_record(self._vmk(), aad, data)
        params = (version, record_type, self.device_id, env["algorithm"], env["nonce"], env["ciphertext"],
                  env["ciphertext_hash"], cc.canonical_json(aad).decode(), now(), record_id)
        if insert:
            self.conn.execute(
                "INSERT INTO records (version, record_type, device_id, algorithm, nonce, ciphertext,"
                " ciphertext_hash, aad, updated_at, record_id, vault_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                params + (self.vault_id,))
        else:
            self.conn.execute(
                "UPDATE records SET version=?, record_type=?, device_id=?, algorithm=?, nonce=?, ciphertext=?,"
                " ciphertext_hash=?, aad=?, updated_at=? WHERE record_id=?", params)
        self.conn.commit()
        self._append_event("CREATE" if insert else "UPDATE", record_id, version, env["ciphertext_hash"])
        return env

    def add(self, entry: dict, record_type: str = "credential") -> str:
        record_id = f"rec-{uuid.uuid4().hex[:8]}"
        self._store(record_id, 1, record_type, self._clean(entry), insert=True)
        return record_id

    def update(self, record_id: str, entry: dict):
        row = self._row(record_id)
        self._store(record_id, row["version"] + 1, row["record_type"], self._clean(entry), insert=False)

    def delete(self, record_id: str):
        row = self._row(record_id)
        self.conn.execute("DELETE FROM records WHERE record_id=?", (record_id,))
        self.conn.commit()
        self._append_event("DELETE", record_id, row["version"] + 1, None)

    def _row(self, record_id: str):
        row = self.conn.execute("SELECT * FROM records WHERE record_id=? AND vault_id=?",
                                (record_id, self.vault_id)).fetchone()
        if not row:
            raise VaultError("Record not found")
        return row

    def get(self, record_id: str) -> dict:
        items, _ = self.list_entries()
        for it in items:
            if it["record_id"] == record_id:
                return it
        raise VaultError("Record not found")

    def list_entries(self, query: str = "", category: str = ""):
        """Decrypts every record, enforcing SHA-256, AES-GCM/AAD and TEVHC version checks.
        Returns (entries, alerts). Search happens client-side on plaintext only."""
        report = self.verify_integrity()
        alerts = list(report.problems)
        expected = report.expected_state
        rows = self.conn.execute("SELECT * FROM records WHERE vault_id=?", (self.vault_id,)).fetchall()
        seen, entries = set(), []
        for r in rows:
            rid, seen_ok = r["record_id"], True
            seen.add(rid)
            exp = expected.get(rid)
            status = "OK"
            if exp is None:
                status = "INJECTED - record not present in audit chain"
            elif exp["deleted"]:
                status = "RESURRECTED - record was deleted"
            elif r["version"] < exp["version"]:
                status = f"ROLLBACK DETECTED - stored v{r['version']}, chain expects v{exp['version']}"
            elif r["ciphertext_hash"] != exp["ciphertext_hash"]:
                status = "TAMPERED - ciphertext hash differs from audit chain"
            aad = json.loads(r["aad"])
            if aad.get("record_id") != rid or aad.get("vault_id") != self.vault_id \
                    or aad.get("record_version") != r["version"]:
                status = "CONTEXT MISMATCH - AAD does not match record metadata"
            data = None
            try:
                data = cc.decrypt_record(self._vmk(), aad, r["nonce"], r["ciphertext"], r["ciphertext_hash"])
            except cc.CryptoError as exc:
                status, seen_ok = f"TAMPERED - {exc}", False
            if status != "OK":
                alerts.append(f"{rid}: {status}")
            if not seen_ok or status != "OK":
                entries.append({"record_id": rid, "version": r["version"], "status": status,
                                "title": f"(unreadable) {rid}", "category": "-", "username": "", "password": "",
                                "url": "", "notes": "", "updated_at": r["updated_at"]})
                continue
            entries.append({"record_id": rid, "version": r["version"], "record_type": r["record_type"],
                            "status": "OK", "updated_at": r["updated_at"], **data})
        for rid, exp in expected.items():
            if not exp["deleted"] and rid not in seen:
                alerts.append(f"{rid}: MISSING - record deleted outside the application")

        if query:
            q = query.lower()
            entries = [e for e in entries if q in e["title"].lower() or q in e["username"].lower()
                       or q in e["url"].lower() or q in e["notes"].lower()]
        if category:
            entries = [e for e in entries if e["category"] == category]
        entries.sort(key=lambda e: e["title"].lower())
        return entries, alerts

    def categories(self) -> list[str]:
        entries, _ = self.list_entries()
        return sorted({e["category"] for e in entries if e["status"] == "OK"})

    def audit_log(self) -> list[dict]:
        return self._events()
