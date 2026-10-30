"""Unit tests for the cryptographic core (Module 1 & 2)."""
import pytest

from cryptvault import crypto_core as cc
from conftest import FAST


def test_pbkdf2_verifier_is_salted_and_constant():
    s1, s2 = cc.random_bytes(16), cc.random_bytes(16)
    h1 = cc.hash_auth_password("pw", s1, FAST)
    assert h1 == cc.hash_auth_password("pw", s1, FAST)          # deterministic for same salt
    assert h1 != cc.hash_auth_password("pw", s2, FAST)          # salt changes output
    assert cc.verify_auth_password("pw", s1, h1, FAST)
    assert not cc.verify_auth_password("pW", s1, h1, FAST)


def test_argon2id_kek_is_256_bit_and_salted():
    salt = cc.random_bytes(16)
    k = cc.derive_kek("master", salt, FAST)
    assert len(k) == 32 and k == cc.derive_kek("master", salt, FAST)
    assert k != cc.derive_kek("master", cc.random_bytes(16), FAST)


def test_vmk_wrap_unwrap_and_wrong_kek():
    kek, vmk = cc.random_bytes(32), cc.random_bytes(32)
    n, w = cc.wrap_vmk(kek, vmk, "usr-1")
    assert cc.unwrap_vmk(kek, n, w, "usr-1") == vmk
    with pytest.raises(cc.CryptoError):
        cc.unwrap_vmk(cc.random_bytes(32), n, w, "usr-1")       # wrong password -> wrong KEK
    with pytest.raises(cc.CryptoError):
        cc.unwrap_vmk(kek, n, w, "usr-2")                       # envelope moved to another user


def test_hkdf_domain_separation():
    vmk = cc.random_bytes(32)
    a, b = cc.record_key(vmk, "v1", "rec-a"), cc.record_key(vmk, "v1", "rec-b")
    assert a != b and a != cc.audit_key(vmk, "v1")


def test_record_roundtrip_and_fresh_nonce():
    vmk = cc.random_bytes(32)
    aad = cc.build_aad("v1", "rec-a", 1, "credential", "dev-1")
    e1, e2 = cc.encrypt_record(vmk, aad, {"p": "x"}), cc.encrypt_record(vmk, aad, {"p": "x"})
    assert e1["nonce"] != e2["nonce"] and e1["ciphertext"] != e2["ciphertext"]
    assert cc.decrypt_record(vmk, aad, e1["nonce"], e1["ciphertext"], e1["ciphertext_hash"]) == {"p": "x"}


@pytest.mark.parametrize("field,value", [("record_id", "rec-b"), ("record_version", 2),
                                         ("device_id", "dev-evil"), ("vault_id", "v2")])
def test_aad_context_binding(field, value):
    vmk = cc.random_bytes(32)
    aad = cc.build_aad("v1", "rec-a", 1, "credential", "dev-1")
    env = cc.encrypt_record(vmk, aad, {"p": "x"})
    with pytest.raises(cc.CryptoError):
        cc.decrypt_record(vmk, {**aad, field: value}, env["nonce"], env["ciphertext"])


def test_bit_flip_detected_by_sha256_and_gcm():
    vmk = cc.random_bytes(32)
    aad = cc.build_aad("v1", "rec-a", 1, "credential", "dev-1")
    env = cc.encrypt_record(vmk, aad, {"p": "x"})
    bad = bytearray(env["ciphertext"]); bad[0] ^= 1
    with pytest.raises(cc.CryptoError, match="SHA-256"):
        cc.decrypt_record(vmk, aad, env["nonce"], bytes(bad), env["ciphertext_hash"])
    with pytest.raises(cc.CryptoError, match="AES-GCM"):
        cc.decrypt_record(vmk, aad, env["nonce"], bytes(bad))
