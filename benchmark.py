"""Measures KDF cost and per-record crypto overhead. Writes results/benchmarks.json."""
import json
import os
import statistics
import tempfile
import time

from cryptvault import crypto_core as cc
from cryptvault.vault import VaultService


def timed(fn, n=5):
    xs = []
    for _ in range(n):
        t = time.perf_counter(); fn(); xs.append((time.perf_counter() - t) * 1000)
    return round(statistics.median(xs), 2)


def main():
    salt, out = os.urandom(16), {}
    out["argon2id_ms_by_memory_mib"] = {
        m: timed(lambda m=m: cc.derive_kek("pw", salt, cc.KdfParams(argon2_memory_kib=m * 1024)), 3)
        for m in (16, 32, 64, 128)}
    out["pbkdf2_ms_by_iterations"] = {
        i: timed(lambda i=i: cc.hash_auth_password("pw", salt, cc.KdfParams(pbkdf2_iterations=i)), 3)
        for i in (100_000, 300_000, 600_000, 1_000_000)}
    vmk = os.urandom(32)
    aad = cc.build_aad("v", "r", 1, "credential", "d")
    rec = {"title": "GitHub", "username": "x" * 30, "password": "y" * 24, "notes": "z" * 200}
    env = cc.encrypt_record(vmk, aad, rec)
    out["record_encrypt_ms"] = timed(lambda: [cc.encrypt_record(vmk, aad, rec) for _ in range(1000)]) / 1000
    out["record_decrypt_ms"] = timed(lambda: [cc.decrypt_record(vmk, aad, env["nonce"], env["ciphertext"],
                                                                env["ciphertext_hash"]) for _ in range(1000)]) / 1000
    out["record_overhead_bytes"] = len(env["ciphertext"]) - len(cc.canonical_json(rec))

    tmp = tempfile.mkdtemp()
    svc = VaultService(os.path.join(tmp, "b.db"), os.path.join(tmp, "c.json"))
    svc.register("bench", "Bench-Master#2026")
    v = svc.unlock("bench", "Bench-Master#2026")
    out["unlock_ms"] = timed(lambda: svc.unlock("bench", "Bench-Master#2026"), 3)
    lst = {}
    for n in (10, 50, 100, 250, 500):
        while len(v.list_entries()[0]) < n:
            v.add({"title": f"site{len(lst)}-{os.urandom(3).hex()}", "username": "u", "password": "p"})
        lst[n] = timed(lambda: v.list_entries(), 3)
    out["list_verify_ms_by_records"] = lst
    os.makedirs("results", exist_ok=True)
    json.dump(out, open("results/benchmarks.json", "w"), indent=2)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
