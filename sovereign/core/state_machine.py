
import sqlite3
import json
import time

class CircuitBreaker:
    """
    Calculus Bound: ถ้าอัตราความผิดพลาด (dE/dt) สูงเกิน Threshold ให้ Trip (ตัดการทำงาน)
    """
    def __init__(self, failure_threshold: int = 3, recovery_time_sec: int = 10):
        self.failure_threshold = failure_threshold
        self.recovery_time = recovery_time_sec
        self.failure_count = 0
        self.state = "CLOSED" # CLOSED = ทำงานปกติ, OPEN = ตัดการทำงาน
        self.last_failure_time = 0

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"
            print("🚨 [Circuit Breaker] TRIPPED! Too many failures. System is now OPEN.")

    def record_success(self):
        self.failure_count = 0
        self.state = "CLOSED"

    def allow_request(self) -> bool:
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.recovery_time:
                print("⚠️ [Circuit Breaker] Half-Open: Testing if system recovered...")
                self.state = "CLOSED"
                self.failure_count = 0
                return True
            return False
        return True

class SQLiteCheckpointer:
    """
    State Machine Theory: บันทึก State ป้องกันการเริ่มใหม่ตั้งแต่ต้น (Resume-Safe)
    """
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
        print(f"💾 [Checkpointer] State saved: {state_hash[:8]}")

    def get_latest_checkpoint(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT state_data FROM checkpoints ORDER BY id DESC LIMIT 1").fetchone()
            if row:
                return json.loads(row[0])
        return {}
