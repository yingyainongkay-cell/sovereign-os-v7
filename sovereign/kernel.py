
import hashlib
from sovereign.core.guards import CentralizedDefense
from sovereign.core.state_machine import CircuitBreaker, SQLiteCheckpointer

class SovereignKernel:
    def __init__(self):
        self.guard = CentralizedDefense()
        self.breaker = CircuitBreaker(failure_threshold=3, recovery_time_sec=5)
        self.checkpointer = SQLiteCheckpointer()

    def _mock_bprh_risk(self, violations: list) -> dict:
        score = 0.9 if violations else 0.1
        tier = "critical" if score > 0.75 else ("medium" if score > 0.5 else "low")
        return {"score": score, "tier": tier}

    def execute_pipeline(self, manifest_code: str) -> dict:
        if not self.breaker.allow_request():
            return {"status": "DENIED", "reason": "CIRCUIT_BREAKER_OPEN"}

        try:
            violations = self.guard.safe_ast_parse(manifest_code)
            if violations:
                self.breaker.record_failure()
                return {"status": "DENIED", "reason": "AST_VIOLATION", "details": violations}

            risk = self._mock_bprh_risk(violations)
            if risk["tier"] in ["high", "critical"]:
                self.breaker.record_failure()
                return {"status": "DENIED", "reason": "HIGH_RISK", "risk": risk}

            # Cryptographic Ground Truth (Ed25519)
            artifact_hash = hashlib.sha256(manifest_code.encode('utf-8')).hexdigest()
            signature = self.guard.generate_signature(artifact_hash)
            
            self.checkpointer.save_checkpoint(artifact_hash, {"status": "VERIFIED", "code": manifest_code})
            self.breaker.record_success()
            
            return {
                "status": "VERIFIED",
                "artifact_hash": artifact_hash,
                "signature": signature,
                "risk_score": risk["score"],
                "message": "Pipeline completed safely with Cryptographic Proof."
            }
        except Exception as e:
            self.breaker.record_failure()
            return {"status": "DENIED", "reason": f"EXCEPTION: {str(e)}"}
