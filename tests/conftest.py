import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptvault.crypto_core import KdfParams  # noqa: E402
from cryptvault.vault import VaultService     # noqa: E402

# Reduced KDF cost so the suite runs in seconds. Production uses DEFAULT_PARAMS.
FAST = KdfParams(pbkdf2_iterations=1_000, argon2_memory_kib=8 * 1024, argon2_iterations=1, argon2_lanes=1)
PW = "Correct-Horse-42!"


@pytest.fixture
def svc(tmp_path):
    return VaultService(str(tmp_path / "v.db"), str(tmp_path / "client.json"), FAST)


@pytest.fixture
def vault(svc):
    svc.register("alice", PW)
    return svc.unlock("alice", PW)
