"""
TEVHC - Tamper-Evident Vault History Chain.

Every state change appends an event whose MAC covers the previous event's MAC:

    mac_n = HMAC-SHA256(audit_key, canonical(seq_n, type_n, record_n, version_n,
                                             ciphertext_hash_n, timestamp_n, mac_{n-1}))

The audit key is HKDF-derived from the VMK, so someone holding only the database
(e.g. a compromised server) cannot forge, reorder, edit or delete events without
the client noticing. Replaying the chain from genesis also yields the expected
latest version + ciphertext hash of every record, which is how rollback is detected.
"""
from __future__ import annotations

import hmac
import hashlib
from dataclasses import dataclass, field

from .crypto_core import canonical_json

GENESIS = "0" * 64


def compute_mac(key: bytes, event: dict, prev_mac: str) -> str:
    body = {k: event[k] for k in ("seq", "event_type", "record_id", "record_version",
                                  "ciphertext_hash", "timestamp")}
    body["prev_mac"] = prev_mac
    return hmac.new(key, canonical_json(body), hashlib.sha256).hexdigest()


@dataclass
class ChainReport:
    valid: bool
    length: int
    head: str
    problems: list[str] = field(default_factory=list)
    # record_id -> {"version": int, "ciphertext_hash": str, "deleted": bool}
    expected_state: dict = field(default_factory=dict)


def verify_chain(key: bytes, events: list[dict]) -> ChainReport:
    prev, problems, state = GENESIS, [], {}
    for i, ev in enumerate(events, start=1):
        if ev["seq"] != i:
            problems.append(f"Sequence gap/reorder at position {i} (found seq {ev['seq']})")
        if ev["prev_mac"] != prev:
            problems.append(f"Broken hash link at seq {ev['seq']}")
        if not hmac.compare_digest(compute_mac(key, ev, prev), ev["event_mac"]):
            problems.append(f"Invalid MAC at seq {ev['seq']} - event forged or edited")
        prev = ev["event_mac"]
        rid = ev["record_id"]
        if rid:
            state[rid] = {"version": ev["record_version"], "ciphertext_hash": ev["ciphertext_hash"],
                          "deleted": ev["event_type"] == "DELETE"}
    return ChainReport(valid=not problems, length=len(events), head=prev,
                       problems=problems, expected_state=state)
