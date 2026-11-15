
import sqlite3
import json
import time
import subprocess

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 3, recovery_time_sec: int = 10):
        self.failure_threshold = failure_threshold
        self.recovery_time = recovery_time_sec
        self.failure_count = 0
        self.state = "CLOSED"
        self.last_failure_time = 0

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"

    def record_success(self):
        self.failure_count = 0
        self.state = "CLOSED"

    def allow_request(self) -> bool:
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.recovery_time:
                self.state = "CLOSED"
                self.failure_count = 0
                return True
            return False
        return True

class SQLiteCheckpointer:
    def __init__(self, db_path="master_stack_state.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    state_hash TEXT,
                    state_data TEXT,
                    timestamp REAL
                )
            """)

    def save_checkpoint(self, state_hash: str, state_data: dict):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO checkpoints (state_hash, state_data, timestamp) VALUES (?, ?, ?)",
                (state_hash, json.dumps(state_data), time.time())
            )

class RuntimeSandbox:
    """Calculus Bound: ป้องกัน Infinite Loop ด้วย Subprocess + Timeout"""
    @staticmethod
    def execute_safely(code: str, timeout_sec: float = 1.0) -> dict:
        try:
            # รันโค้ดใน Python process ใหม่
            result = subprocess.run(
                ["python3", "-c", code],
                capture_output=True, text=True, timeout=timeout_sec
            )
            if result.returncode == 0:
                return {"status": "SUCCESS", "output": result.stdout.strip()}
            else:
                return {"status": "FAILED", "error": result.stderr.strip()}
        except subprocess.TimeoutExpired:
            return {"status": "BLOCKED", "reason": "Execution Timeout Exceeded (Infinite Loop Protection)"}
