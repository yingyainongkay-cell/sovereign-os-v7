
import pytest
from sovereign.kernel import SovereignKernel

@pytest.fixture
def kernel():
    return SovereignKernel()

@pytest.mark.parametrize("attack_id, payload, expected_status, expected_reason", [
    ("ATK-01", "import os\nos.system('rm -rf /')", "DENIED", "AST_VIOLATION"),
    ("ATK-02", "getattr(__builtins__, 'eval')('print(1)')", "DENIED", "AST_VIOLATION"),
    ("ATK-03", "def add(a, b):\n    return a + b", "VERIFIED", None),
    ("ATK-04", "def broken_code(:", "DENIED", "AST_VIOLATION"),
])
def test_red_team_attacks(kernel, attack_id, payload, expected_status, expected_reason):
    result = kernel.execute_pipeline(payload)
    assert result["status"] == expected_status
    if expected_status == "VERIFIED":
        assert "signature" in result
        assert len(result["signature"]) == 128 # Ed25519 hex length
    if expected_reason:
        assert result["reason"] == expected_reason

def test_circuit_breaker_opens_on_cascading_failure(kernel):
    bad_payload = "import os\nos.system('malicious')"
    for _ in range(3):
        kernel.execute_pipeline(bad_payload)
    result = kernel.execute_pipeline(bad_payload)
    assert result["status"] == "DENIED"
    assert result["reason"] == "CIRCUIT_BREAKER_OPEN"
