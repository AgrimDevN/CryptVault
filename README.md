# CryptVault

A multi-layer secure credential manager using hybrid cryptographic techniques
(BCSE309L – Cryptography and Network Security Laboratory, Review 2 build).

## Quick start

```bash
pip install -r requirements.txt
python app.py                 # web app  -> http://127.0.0.1:5000
python demo.py                # console walkthrough + attack simulations
python -m pytest -v           # 33 unit / integration / attack tests
python benchmark.py           # KDF and per-record timing -> results/benchmarks.json
```

Requires Python 3.10+ and `cryptography` 44+. Argon2id uses OpenSSL when it supports it
(OpenSSL 3.2+); otherwise it falls back to `argon2-cffi`, which produces identical keys.

## Key hierarchy

```
Master password ──PBKDF2-SHA256 (600k, salt₁)──► auth_hash      (login verifier only)
               └─Argon2id (64 MiB, t=3, p=4, salt₂)──► KEK
                                                    │ AES-256-GCM unwrap
                                                    ▼
                                VMK (random 256-bit vault master key)
                                    │ HKDF-SHA256 (domain-separated)
                     ┌──────────────┴───────────────┐
             per-record key                   audit MAC key
                     │ AES-256-GCM + AAD               │ HMAC-SHA256 hash chain
              encrypted record                    TEVHC audit log
```

## Project layout

| Path | Purpose |
|---|---|
| `cryptvault/crypto_core.py` | PBKDF2, Argon2id, VMK wrap/unwrap, HKDF, CBLKE AES-256-GCM encryption |
| `cryptvault/audit.py` | TEVHC – HMAC-linked tamper-evident history chain + verifier |
| `cryptvault/vault.py` | Vault service: register/unlock, CRUD, rollback & tamper detection, master-password change |
| `cryptvault/passwords.py` | CSPRNG password generator, entropy-based strength analyser |
| `cryptvault/db.py` | SQLite schema (ciphertext only) |
| `app.py` | Flask web app (CSRF, CSP headers, auto-lock, in-memory key store) |
| `templates/`, `static/` | HTML / CSS / JS front end |
| `tests/` | pytest suite incl. attack simulations |
| `demo.py`, `benchmark.py` | Console demo and performance measurements |

## Status (Review 2)

| Module | Status |
|---|---|
| M1 Authentication & vault unlock | Completed |
| M2 CBLKE record encryption engine | Completed |
| M3 Vault management & password tools | Completed |
| M4 TEVHC audit chain | Completed |
| M5 Versioning & rollback detection / sync | In progress (local detection done; multi-device sync pending) |
| M6 Device key envelopes (X25519) & selective sharing | Not started |
| M7 Encrypted backup & recovery, optional TOTP 2FA | Not started |

## Environment variables

* `CRYPTVAULT_SECRET` – Flask session secret (random per start if unset)
* `CRYPTVAULT_TIMEOUT` – auto-lock idle timeout in seconds (default 300)
* `CRYPTVAULT_INSTANCE` – folder for the database and device state (default `./instance`)
