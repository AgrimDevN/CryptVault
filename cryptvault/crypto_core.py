"""
CryptVault - Cryptographic core.

Key hierarchy (the vault key is never derived directly from the master password):

    Master password
        |-- PBKDF2-HMAC-SHA256 (auth_salt, 600k iters) --> auth_hash   (login verifier only)
        |-- Argon2id (kek_salt, 64 MiB, t=3, p=4)      --> KEK         (key-encryption key)
                                                            |
                                     AES-256-GCM unwrap     v
                                                           VMK (random 256-bit vault master key)
                                                            |
                                  HKDF-SHA256 (domain-separated "info" labels)
                                  |                                  |
                         Record Encryption Key               Audit MAC key (TEVHC)
                                  |
                     AES-256-GCM + context-bound AAD (CBLKE)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PROTOCOL_VERSION = 1
KEY_LEN = 32            # 256-bit keys
NONCE_LEN = 12          # 96-bit GCM nonce (NIST SP 800-38D recommended size)
SALT_LEN = 16
VERIFIER_PLAINTEXT = b"CRYPTVAULT-VAULT-VERIFIER-v1"


class CryptoError(Exception):
    """Raised when authentication / decryption / integrity checks fail."""


@dataclass(frozen=True)
class KdfParams:
    """Tunable cost parameters (lowered only inside unit tests)."""
    pbkdf2_iterations: int = 600_000      # OWASP 2023 recommendation for PBKDF2-SHA256
    argon2_memory_kib: int = 64 * 1024    # 64 MiB
    argon2_iterations: int = 3
    argon2_lanes: int = 4


DEFAULT_PARAMS = KdfParams()


# ---------------------------------------------------------------- helpers
def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def canonical_json(obj: dict) -> bytes:
    """Deterministic JSON encoding so AAD / MAC inputs are byte-identical every time."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- Layer 1: authentication
def hash_auth_password(password: str, salt: bytes, params: KdfParams = DEFAULT_PARAMS) -> bytes:
    """PBKDF2-HMAC-SHA256 login verifier. Stored server-side; never used as an encryption key."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt,
                     iterations=params.pbkdf2_iterations)
    return kdf.derive(password.encode())


def verify_auth_password(password: str, salt: bytes, expected: bytes,
                         params: KdfParams = DEFAULT_PARAMS) -> bool:
    return hmac.compare_digest(hash_auth_password(password, salt, params), expected)  # constant time


# ---------------------------------------------------------------- Layer 2: KEK
def _argon2id_openssl(password: bytes, salt: bytes, params: KdfParams) -> bytes:
    # Needs cryptography >= 44 linked against OpenSSL >= 3.2.
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    return Argon2id(salt=salt, length=KEY_LEN, iterations=params.argon2_iterations,
                    lanes=params.argon2_lanes, memory_cost=params.argon2_memory_kib).derive(password)


def _argon2id_cffi(password: bytes, salt: bytes, params: KdfParams) -> bytes:
    # Reference libargon2 (argon2-cffi). Same RFC 9106 Argon2id v1.3 output as OpenSSL.
    from argon2.low_level import Type, hash_secret_raw
    return hash_secret_raw(password, salt, time_cost=params.argon2_iterations,
                           memory_cost=params.argon2_memory_kib, parallelism=params.argon2_lanes,
                           hash_len=KEY_LEN, type=Type.ID, version=19)


def _pick_argon2id():
    try:
        _argon2id_openssl(b"probe", b"\0" * SALT_LEN, KdfParams(argon2_memory_kib=8, argon2_iterations=1,
                                                                argon2_lanes=1))
        return _argon2id_openssl
    except (ImportError, UnsupportedAlgorithm):
        pass
    try:
        import argon2.low_level  # noqa: F401
        return _argon2id_cffi
    except ImportError as exc:
        raise ImportError("Argon2id unavailable: this OpenSSL build lacks it (needs OpenSSL 3.2+). "
                          "Install the fallback with `pip install argon2-cffi`.") from exc


_ARGON2ID = _pick_argon2id()
ARGON2_BACKEND = "OpenSSL" if _ARGON2ID is _argon2id_openssl else "argon2-cffi"


def derive_kek(password: str, salt: bytes, params: KdfParams = DEFAULT_PARAMS) -> bytes:
    """Argon2id memory-hard KDF: master password -> Key Encryption Key."""
    return _ARGON2ID(password.encode(), salt, params)


# ---------------------------------------------------------------- Layer 3: VMK wrap / unwrap
def _wrap_aad(user_id: str) -> bytes:
    return canonical_json({"p": PROTOCOL_VERSION, "purpose": "vmk-wrap", "user_id": user_id})


def wrap_vmk(kek: bytes, vmk: bytes, user_id: str) -> tuple[bytes, bytes]:
    nonce = random_bytes(NONCE_LEN)
    return nonce, AESGCM(kek).encrypt(nonce, vmk, _wrap_aad(user_id))


def unwrap_vmk(kek: bytes, nonce: bytes, wrapped: bytes, user_id: str) -> bytes:
    try:
        return AESGCM(kek).decrypt(nonce, wrapped, _wrap_aad(user_id))
    except InvalidTag as exc:
        raise CryptoError("VMK unwrap failed - wrong master password or tampered key envelope") from exc


def make_vault_verifier(vmk: bytes, vault_id: str) -> tuple[bytes, bytes]:
    nonce = random_bytes(NONCE_LEN)
    return nonce, AESGCM(vmk).encrypt(nonce, VERIFIER_PLAINTEXT, vault_id.encode())


def check_vault_verifier(vmk: bytes, vault_id: str, nonce: bytes, blob: bytes) -> bool:
    try:
        return AESGCM(vmk).decrypt(nonce, blob, vault_id.encode()) == VERIFIER_PLAINTEXT
    except InvalidTag:
        return False


# ---------------------------------------------------------------- Layer 4: HKDF sub-keys
def hkdf(vmk: bytes, info: str, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt,
                info=info.encode()).derive(vmk)


def record_key(vmk: bytes, vault_id: str, record_id: str) -> bytes:
    """Per-record key: compromise of one record key never exposes another record."""
    return hkdf(vmk, f"cryptvault/v{PROTOCOL_VERSION}/record|{record_id}", salt=vault_id.encode())


def audit_key(vmk: bytes, vault_id: str) -> bytes:
    return hkdf(vmk, f"cryptvault/v{PROTOCOL_VERSION}/audit-chain", salt=vault_id.encode())


# ---------------------------------------------------------------- Layer 5: CBLKE record encryption
def build_aad(vault_id: str, record_id: str, version: int, record_type: str, device_id: str) -> dict:
    return {"protocol_version": PROTOCOL_VERSION, "vault_id": vault_id, "record_id": record_id,
            "record_version": version, "record_type": record_type, "device_id": device_id}


def encrypt_record(vmk: bytes, aad: dict, plaintext: dict) -> dict:
    """Context-Bound Layered Key Envelope: HKDF key + AES-256-GCM + AAD binding."""
    key = record_key(vmk, aad["vault_id"], aad["record_id"])
    nonce = random_bytes(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, canonical_json(plaintext), canonical_json(aad))
    return {"algorithm": "AES-256-GCM", "nonce": nonce, "ciphertext": ct,
            "ciphertext_hash": sha256_hex(nonce + ct), "aad": aad}


def decrypt_record(vmk: bytes, aad: dict, nonce: bytes, ciphertext: bytes,
                   expected_hash: str | None = None) -> dict:
    if expected_hash is not None and not hmac.compare_digest(sha256_hex(nonce + ciphertext), expected_hash):
        raise CryptoError("SHA-256 integrity check failed - ciphertext modified at rest")
    key = record_key(vmk, aad["vault_id"], aad["record_id"])
    try:
        return json.loads(AESGCM(key).decrypt(nonce, ciphertext, canonical_json(aad)))
    except InvalidTag as exc:
        raise CryptoError("AES-GCM authentication failed - ciphertext or context (AAD) tampered") from exc
