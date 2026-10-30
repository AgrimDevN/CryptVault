"""Integration + attack-simulation tests for vault, TEVHC and rollback detection (Modules 3-5)."""
import pytest

from cryptvault.passwords import analyse_strength, generate_password
from cryptvault.vault import VaultError
from conftest import PW

ENTRY = {"title": "GitHub", "category": "Work", "username": "alice@vit.ac.in",
         "password": "gh-S3cret!Token#2026", "url": "https://github.com", "notes": "2FA on"}


def test_register_unlock_and_wrong_password(svc):
    svc.register("bob", PW)
    assert svc.unlock("bob", PW).vault_id.startswith("vault-")
    with pytest.raises(VaultError):
        svc.unlock("bob", "wrong-password")


def test_same_password_gives_independent_vault_keys(svc):
    svc.register("u1", PW); svc.register("u2", PW)
    assert svc.unlock("u1", PW).vmk != svc.unlock("u2", PW).vmk


def test_crud_search_and_versions(vault):
    rid = vault.add(ENTRY)
    vault.add({**ENTRY, "title": "SBI NetBanking", "category": "Banking", "url": "https://onlinesbi.sbi"})
    assert len(vault.list_entries()[0]) == 2
    assert [e["title"] for e in vault.list_entries("git")[0]] == ["GitHub"]
    assert [e["title"] for e in vault.list_entries(category="Banking")[0]] == ["SBI NetBanking"]
    vault.update(rid, {**ENTRY, "password": "N3w-Passw0rd!xyz"})
    e = vault.get(rid)
    assert e["version"] == 2 and e["password"] == "N3w-Passw0rd!xyz"
    vault.delete(rid)
    entries, alerts = vault.list_entries()
    assert len(entries) == 1 and alerts == []


def test_database_contains_no_plaintext(svc, vault, tmp_path):
    vault.add(ENTRY)
    raw = (tmp_path / "v.db").read_bytes()
    for secret in (ENTRY["password"], ENTRY["username"], "GitHub", PW):
        assert secret.encode() not in raw


def test_ciphertext_tampering_detected(vault):
    rid = vault.add(ENTRY)
    ct = bytearray(vault.conn.execute("SELECT ciphertext FROM records WHERE record_id=?", (rid,)).fetchone()[0])
    ct[5] ^= 0x01                                   # attacker flips one bit at rest
    vault.conn.execute("UPDATE records SET ciphertext=? WHERE record_id=?", (bytes(ct), rid))
    entries, alerts = vault.list_entries()
    assert entries[0]["status"].startswith("TAMPERED") and alerts


def test_record_swap_detected_by_aad(vault):
    a, b = vault.add(ENTRY), vault.add({**ENTRY, "title": "Gmail"})
    row = vault.conn.execute("SELECT nonce, ciphertext, ciphertext_hash FROM records WHERE record_id=?", (a,)).fetchone()
    vault.conn.execute("UPDATE records SET nonce=?, ciphertext=?, ciphertext_hash=? WHERE record_id=?",
                       (row["nonce"], row["ciphertext"], row["ciphertext_hash"], b))
    statuses = {e["record_id"]: e["status"] for e in vault.list_entries()[0]}
    assert statuses[a] == "OK" and statuses[b] != "OK"


def test_rollback_attack_detected(vault):
    rid = vault.add(ENTRY)
    old = dict(vault.conn.execute("SELECT * FROM records WHERE record_id=?", (rid,)).fetchone())
    vault.update(rid, {**ENTRY, "password": "Rotated-Pass#99"})
    # attacker restores the old, perfectly valid v1 ciphertext row
    vault.conn.execute("UPDATE records SET version=?, nonce=?, ciphertext=?, ciphertext_hash=?, aad=? WHERE record_id=?",
                       (old["version"], old["nonce"], old["ciphertext"], old["ciphertext_hash"], old["aad"], rid))
    entries, alerts = vault.list_entries()
    assert entries[0]["status"].startswith("ROLLBACK DETECTED")


def test_audit_event_forgery_detected(vault):
    vault.add(ENTRY)
    vault.conn.execute("UPDATE audit_events SET event_type='DELETE' WHERE seq=2")
    rep = vault.verify_integrity()
    assert not rep.valid and any("Invalid MAC" in p for p in rep.problems)


def test_history_truncation_detected(vault):
    vault.add(ENTRY); vault.add({**ENTRY, "title": "Gmail"})
    vault.conn.execute("DELETE FROM audit_events WHERE seq=(SELECT MAX(seq) FROM audit_events)")
    rep = vault.verify_integrity()
    assert not rep.valid and any("truncated" in p for p in rep.problems)


def test_injected_and_deleted_records_detected(vault):
    rid = vault.add(ENTRY)
    vault.conn.execute("DELETE FROM records WHERE record_id=?", (rid,))
    assert any("MISSING" in a for a in vault.list_entries()[1])


def test_change_master_password_rewraps_only(svc, vault):
    rid = vault.add(ENTRY)
    ct_before = svc.conn.execute("SELECT ciphertext FROM records").fetchone()[0]
    svc.change_master_password("alice", PW, "Brand-New-Master#7")
    assert svc.conn.execute("SELECT ciphertext FROM records").fetchone()[0] == ct_before
    with pytest.raises(VaultError):
        svc.unlock("alice", PW)
    assert svc.unlock("alice", "Brand-New-Master#7").get(rid)["password"] == ENTRY["password"]


def test_lock_wipes_key(vault):
    vault.lock()
    with pytest.raises(VaultError):
        vault.list_entries()


def test_generator_policy():
    pws = {generate_password(24) for _ in range(200)}
    assert len(pws) == 200
    for p in pws:
        assert len(p) == 24 and analyse_strength(p)["policy_passed"]
    with pytest.raises(ValueError):
        generate_password(4)


@pytest.mark.parametrize("pw,score", [("password", 0), ("abcd1234", 0), ("Summer2026", 2),
                                      ("Tr0ub4dor&3xK!", 3), ("x7#Qm!v9Lp@2Rz$8Wk", 4)])
def test_strength_scores(pw, score):
    assert analyse_strength(pw)["score"] == score
