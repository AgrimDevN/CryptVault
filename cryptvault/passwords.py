"""Password generator (CSPRNG) and policy-based strength analyser."""
from __future__ import annotations

import math
import re
import secrets
import string

AMBIGUOUS = set("Il1O0o|`'\"")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/~"

# Small built-in deny-list (top leaked passwords); extend with a larger list if needed.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123", "111111",
    "password1", "iloveyou", "admin", "welcome", "monkey", "dragon", "letmein", "qwerty123",
    "football", "1234567890", "sunshine", "princess", "passw0rd", "master", "login", "starwars",
}

POLICY = {"min_length": 12, "require_upper": True, "require_lower": True,
          "require_digit": True, "require_symbol": True}


def generate_password(length: int = 20, upper: bool = True, lower: bool = True, digits: bool = True,
                      symbols: bool = True, exclude_ambiguous: bool = True) -> str:
    if not 8 <= length <= 128:
        raise ValueError("length must be between 8 and 128")
    pools = []
    if upper:
        pools.append(string.ascii_uppercase)
    if lower:
        pools.append(string.ascii_lowercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)
    if not pools:
        raise ValueError("select at least one character class")
    if exclude_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
    alphabet = "".join(pools)
    while True:
        # guarantee one char from every selected class, fill the rest uniformly, then shuffle
        chars = [secrets.choice(p) for p in pools]
        chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
        secrets.SystemRandom().shuffle(chars)
        pw = "".join(chars)
        # rejection sampling: discard the rare outputs with predictable runs ("aaa", "1234")
        if not _has_sequence(pw) and not re.search(r"(.)\1{2,}", pw):
            return pw


def _pool_size(pw: str) -> int:
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"\d", pw):
        size += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        size += 33
    return size


def _has_sequence(pw: str, run: int = 4) -> bool:
    low = pw.lower()
    for i in range(len(low) - run + 1):
        chunk = low[i:i + run]
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(run - 1)):
            return True
        if all(ord(chunk[j]) - ord(chunk[j + 1]) == 1 for j in range(run - 1)):
            return True
    return False


def analyse_strength(pw: str) -> dict:
    """Returns entropy estimate, 0-4 score, label, policy checks and feedback."""
    checks = {
        "length": len(pw) >= POLICY["min_length"],
        "upper": bool(re.search(r"[A-Z]", pw)),
        "lower": bool(re.search(r"[a-z]", pw)),
        "digit": bool(re.search(r"\d", pw)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", pw)),
        "not_common": pw.lower() not in COMMON_PASSWORDS,
        "no_sequence": not _has_sequence(pw),
        "no_repeats": not re.search(r"(.)\1{2,}", pw),
    }
    entropy = len(pw) * math.log2(_pool_size(pw)) if pw else 0.0
    # penalties for predictable structure
    if not checks["no_sequence"]:
        entropy *= 0.5
    if not checks["no_repeats"]:
        entropy *= 0.8
    if not checks["not_common"]:
        entropy = min(entropy, 5.0)

    score = 0 if entropy < 28 else 1 if entropy < 40 else 2 if entropy < 64 else 3 if entropy < 100 else 4
    if not checks["not_common"]:
        score = 0
    labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
    hints = {
        "length": f"Use at least {POLICY['min_length']} characters",
        "upper": "Add an uppercase letter", "lower": "Add a lowercase letter",
        "digit": "Add a digit", "symbol": "Add a symbol",
        "not_common": "This is a commonly leaked password",
        "no_sequence": "Avoid sequences like 'abcd' or '1234'",
        "no_repeats": "Avoid repeating the same character 3+ times",
    }
    feedback = [hints[k] for k, ok in checks.items() if not ok]
    return {"entropy_bits": round(entropy, 1), "score": score, "label": labels[score],
            "policy_passed": all(checks.values()), "checks": checks, "feedback": feedback}
