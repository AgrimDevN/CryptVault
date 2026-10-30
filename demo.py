"""
CryptVault - console demonstration for Review 2.

Walks through the key hierarchy with production KDF parameters, then simulates
attacks against the stored database and shows that each one is detected.

    python demo.py
"""
import os
import shutil
import tempfile
import time

from cryptvault import crypto_core as cc
from cryptvault.passwords import analyse_strength, generate_password
from cryptvault.vault import VaultService

LINE = "=" * 72


def h(title):
    print(f"\n{LINE}\n  {title}\n{LINE}")


def main():
    tmp = tempfile.mkdtemp(prefix="cryptvault-demo-")
    db = os.path.join(tmp, "vault.db")
    svc = VaultService(db, os.path.join(tmp, "client.json"))
    master = "Vit@Vellore#CNS-2026"

    h("1. REGISTRATION  (master password -> PBKDF2 verifier + Argon2id KEK -> wrapped random VMK)")
    t = time.perf_counter(); svc.register("agrim", master); t = (time.perf_counter() - t) * 1000
    u = svc.conn.execute("SELECT * FROM users").fetchone()
    print(f"  user_id         : {u['user_id']}            vault_id: {u['vault_id']}")
    print(f"  auth_salt       : {u['auth_salt'].hex()}")
    print(f"  auth_hash       : {u['auth_hash'].hex()[:48]}...  (PBKDF2-SHA256, 600k)")
    print(f"  kek_salt        : {u['kek_salt'].hex()}")
    print(f"  vmk_wrapped     : {u['vmk_wrapped'].hex()[:48]}...  (AES-256-GCM, 48 B)")
    print(f"  registration    : {t:.0f} ms")

    h("2. LOGIN + VAULT UNLOCK")
    t = time.perf_counter(); v = svc.unlock("agrim", master); t = (time.perf_counter() - t) * 1000
    print(f"  [OK] PBKDF2 verifier matched (constant-time compare)")
    print(f"  [OK] Argon2id(m=64 MiB, t=3, p=4) -> KEK -> VMK unwrapped, verifier valid")
    print(f"  unlock time     : {t:.0f} ms")
    try:
        svc.unlock("agrim", "wrong-guess-123")
    except Exception as exc:  # noqa: BLE001
        print(f"  [BLOCKED] wrong password -> {type(exc).__name__}: {exc}")

    h("3. CBLKE RECORD ENCRYPTION  (HKDF per-record key + AES-256-GCM + AAD)")
    ids = {}
    for e in [
        {"title": "GitHub", "category": "Work", "username": "agrim.dev@vitstudent.ac.in",
         "password": generate_password(20), "url": "https://github.com"},
        {"title": "VTOP Portal", "category": "Academic", "username": "23BAI0049",
         "password": generate_password(16), "url": "https://vtop.vit.ac.in"},
        {"title": "SBI NetBanking", "category": "Banking", "username": "agrim_d",
         "password": generate_password(24), "url": "https://onlinesbi.sbi"},
    ]:
        ids[e["title"]] = v.add(e)
    row = svc.conn.execute("SELECT * FROM records WHERE record_id=?", (ids["GitHub"],)).fetchone()
    print(f"  record_id       : {row['record_id']}   version: {row['version']}   algorithm: {row['algorithm']}")
    print(f"  nonce (96-bit)  : {row['nonce'].hex()}")
    print(f"  ciphertext      : {row['ciphertext'].hex()[:56]}...")
    print(f"  ciphertext_hash : {row['ciphertext_hash'][:56]}...")
    print(f"  aad             : {row['aad']}")
    raw = open(db, "rb").read()
    print(f"  plaintext 'GitHub' / username present in DB file? -> "
          f"{b'GitHub' in raw or b'agrim.dev' in raw}")

    h("4. DECRYPT + SEARCH (client-side, after integrity checks)")
    for e in v.list_entries()[0]:
        print(f"  {e['title']:<16} {e['category']:<9} {e['username']:<28} {e['password'][:6]}****  v{e['version']}  {e['status']}")
    print(f"  search 'vtop'   -> {[e['title'] for e in v.list_entries('vtop')[0]]}")
    print(f"  category=Banking-> {[e['title'] for e in v.list_entries(category='Banking')[0]]}")

    h("5. TEVHC AUDIT CHAIN")
    v.update(ids["GitHub"], {**v.get(ids["GitHub"]), "password": generate_password(20)})
    for ev in v.audit_log():
        print(f"  #{ev['seq']:<2} {ev['event_type']:<12} {ev['record_id'] or '-':<13} {('v' + str(ev['record_version'])) if ev['record_version'] else '-':<5}"
              f" prev={ev['prev_mac'][:10]}  mac={ev['event_mac'][:10]}")
    rep = v.verify_integrity()
    print(f"  chain valid     : {rep.valid}   length: {rep.length}   head: {rep.head[:16]}...")

    h("6. ATTACK SIMULATIONS ON THE STORED DATABASE")
    c = svc.conn
    # (a) bit flip
    ct = bytearray(c.execute("SELECT ciphertext FROM records WHERE record_id=?", (ids["VTOP Portal"],)).fetchone()[0])
    ct[3] ^= 1
    c.execute("UPDATE records SET ciphertext=? WHERE record_id=?", (bytes(ct), ids["VTOP Portal"]))
    # (b) rollback: restore GitHub v1 row
    old = c.execute("SELECT * FROM audit_events WHERE record_id=? ORDER BY seq", (ids["GitHub"],)).fetchone()
    print(f"  (a) flipped 1 bit of VTOP Portal ciphertext")
    snap = dict(c.execute("SELECT * FROM records WHERE record_id=?", (ids["SBI NetBanking"],)).fetchone())
    v.update(ids["SBI NetBanking"], {**v.get(ids["SBI NetBanking"]), "password": generate_password(24)})
    c.execute("UPDATE records SET version=?, nonce=?, ciphertext=?, ciphertext_hash=?, aad=? WHERE record_id=?",
              (snap["version"], snap["nonce"], snap["ciphertext"], snap["ciphertext_hash"], snap["aad"],
               ids["SBI NetBanking"]))
    print(f"  (b) replaced SBI NetBanking v2 with its old (valid) v1 ciphertext  -> rollback")
    entries, alerts = v.list_entries()
    for a in alerts:
        print(f"      DETECTED: {a}")
    c.execute("UPDATE audit_events SET event_type='DELETE' WHERE seq=?", (old["seq"],))
    print(f"  (c) edited audit event #{old['seq']} CREATE -> DELETE")
    for p in v.verify_integrity().problems:
        print(f"      DETECTED: {p}")
    c.execute("DELETE FROM audit_events WHERE seq=(SELECT MAX(seq) FROM audit_events WHERE vault_id=?)", (v.vault_id,))
    print(f"  (d) deleted the newest audit event (history truncation)")
    print(f"      DETECTED: {[p for p in v.verify_integrity().problems if 'truncated' in p][0]}")

    h("7. PASSWORD GENERATOR + STRENGTH ANALYSER")
    for pw in ["password", "abcd1234", "Summer2026", "Tr0ub4dor&3xK!", generate_password(20)]:
        s = analyse_strength(pw)
        print(f"  {pw:<22} score {s['score']}/4  {s['label']:<12} {s['entropy_bits']:>6} bits  policy={'PASS' if s['policy_passed'] else 'FAIL'}")

    v.lock()
    print(f"\n  Vault locked, VMK wiped: {not any(v.vmk)}")
    shutil.rmtree(tmp)


if __name__ == "__main__":
    main()
