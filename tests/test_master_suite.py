
import pytest
from sovereign.kernel import SovereignKernel

@pytest.fixture
def kernel():
    return SovereignKernel()

@pytest.mark.parametrize("attack_id, payload, expected_status", [
    ("ATK-01", "import os\nos.system('rm -rf /')", "DENIED"),
    ("ATK-02", "getattr(__builtins__, 'eval')('print(1)')", "DENIED"),
    ("ATK-03", "def add(a, b):\n    return a + b", "VERIFIED"),
    ("ATK-04", "def broken_code(:", "DENIED"),
    ("ATK-06", "while True:\n    pass", "DENIED"), # <--- Sandbox Timeout Test
])
def test_red_team_attacks(kernel, attack_id, payload, expected_status):
    result = kernel.execute_pipeline(payload)
    assert result["status"] == expected_status, f"[{attack_id}] Expected {expected_status} but got {result['status']}"
    
    # ตรวจสอบ Multi-Sig (Phase C)
    if expected_status == "VERIFIED":
        attestation = result["attestation"]
        assert len(attestation["signatures"]) == 2 # บังคับ 2-of-3
        assert attestation["quorum"] == "2-of-3"

def test_circuit_breaker_opens_on_cascading_failure(kernel):
    bad_payload = "import os\nos.system('malicious')"
    for _ in range(3):
        kernel.execute_pipeline(bad_payload)
    result = kernel.execute_pipeline(bad_payload)
    assert result["status"] == "DENIED"
    assert result["reason"] == "CIRCUIT_BREAKER_OPEN"
