
import hashlib
from sovereign.core.guards import CentralizedDefense
from sovereign.core.state_machine import CircuitBreaker, SQLiteCheckpointer, RuntimeSandbox

class SovereignKernel:
    def __init__(self):
        self.guard = CentralizedDefense()
        self.breaker = CircuitBreaker(failure_threshold=3, recovery_time_sec=5)
        self.checkpointer = SQLiteCheckpointer()
        self.sandbox = RuntimeSandbox()

    def _mock_bprh_risk(self, violations: list) -> dict:
        score = 0.9 if violations else 0.1
        tier = "critical" if score > 0.75 else ("medium" if score > 0.5 else "low")
        return {"score": score, "tier": tier}

    def execute_pipeline(self, manifest_code: str) -> dict:
        if not self.breaker.allow_request():
            return {"status": "DENIED", "reason": "CIRCUIT_BREAKER_OPEN"}

        try:
            # 1. Static AST Check
            violations = self.guard.safe_ast_parse(manifest_code)
            if violations:
                self.breaker.record_failure()
                return {"status": "DENIED", "reason": "AST_VIOLATION", "details": violations}

            # 2. Risk Engine
            risk = self._mock_bprh_risk(violations)
            if risk["tier"] in ["high", "critical"]:
                self.breaker.record_failure()
                return {"status": "DENIED", "reason": "HIGH_RISK", "risk": risk}

            # 3. Runtime Sandbox Execution (Phase A)
            sandbox_result = self.sandbox.execute_safely(manifest_code, timeout_sec=1.0)
            if sandbox_result["status"] == "BLOCKED":
                self.breaker.record_failure()
                return {"status": "DENIED", "reason": "SANDBOX_TIMEOUT", "details": sandbox_result}

            # 4. Cryptographic Multi-Sig (Phase C)
            artifact_hash = hashlib.sha256(manifest_code.encode('utf-8')).hexdigest()
            attestation = self.guard.generate_multi_sig(artifact_hash) # Default 2-of-3
            
            self.checkpointer.save_checkpoint(artifact_hash, {"status": "VERIFIED", "code": manifest_code})
            self.breaker.record_success()
            
            return {
                "status": "VERIFIED",
                "artifact_hash": artifact_hash,
                "attestation": attestation,
                "execution_output": sandbox_result.get("output"),
                "risk_score": risk["score"]
            }
        except Exception as e:
            self.breaker.record_failure()
            return {"status": "DENIED", "reason": f"EXCEPTION: {str(e)}"}
