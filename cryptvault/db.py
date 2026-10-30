"""SQLite storage. The server-side database holds ONLY ciphertext, salts, hashes and metadata."""
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id        TEXT PRIMARY KEY,
    username       TEXT UNIQUE NOT NULL,
    auth_salt      BLOB NOT NULL,      -- PBKDF2 salt
    auth_hash      BLOB NOT NULL,      -- PBKDF2-SHA256 login verifier
    kek_salt       BLOB NOT NULL,      -- Argon2id salt
    vmk_nonce      BLOB NOT NULL,
    vmk_wrapped    BLOB NOT NULL,      -- AES-256-GCM(KEK, VMK)
    vault_id       TEXT UNIQUE NOT NULL,
    verifier_nonce BLOB NOT NULL,
    verifier_blob  BLOB NOT NULL,      -- AES-256-GCM(VMK, constant)
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
    record_id       TEXT PRIMARY KEY,
    vault_id        TEXT NOT NULL,
    version         INTEGER NOT NULL,
    record_type     TEXT NOT NULL,
    device_id       TEXT NOT NULL,
    algorithm       TEXT NOT NULL,
    nonce           BLOB NOT NULL,
    ciphertext      BLOB NOT NULL,
    ciphertext_hash TEXT NOT NULL,     -- SHA-256(nonce || ciphertext)
    aad             TEXT NOT NULL,     -- canonical JSON context bound into GCM tag
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    vault_id        TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    event_type      TEXT NOT NULL,     -- VAULT_CREATE | CREATE | UPDATE | DELETE | KEY_ROTATE
    record_id       TEXT,
    record_version  INTEGER,
    ciphertext_hash TEXT,
    timestamp       TEXT NOT NULL,
    prev_mac        TEXT NOT NULL,
    event_mac       TEXT NOT NULL,     -- HMAC-SHA256 hash-chained
    PRIMARY KEY (vault_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_records_vault ON records(vault_id);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn
