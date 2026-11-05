"""
Audit and Assessment Planner Model
Manages security compliance audit trails, allowlists, and bounded assessment planner tasks.
"""
from database.db import get_db_connection

class AuditModel:
    @staticmethod
    def get_logs(limit: int = 50):
        conn = get_db_connection()
        logs = conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return logs

class AllowlistModel:
    @staticmethod
    def get_all():
        conn = get_db_connection()
        targets = conn.execute("SELECT * FROM target_allowlist ORDER BY id ASC").fetchall()
        conn.close()
        return targets

    @staticmethod
    def add(target: str, label: str = None, description: str = None):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO target_allowlist (target, label, description, is_approved)
            VALUES (?, ?, ?, 1)
        """, (target, label, description))
        conn.commit()
        last_id = cur.lastrowid
        conn.close()
        return last_id

    @staticmethod
    def delete(target_id: int):
        conn = get_db_connection()
        conn.execute("DELETE FROM target_allowlist WHERE id = ?", (target_id,))
        conn.commit()
        conn.close()

class PlannerModel:
    @staticmethod
    def get_all():
        conn = get_db_connection()
        plans = conn.execute("SELECT * FROM assessment_plans ORDER BY id ASC").fetchall()
        conn.close()
        return plans

    @staticmethod
    def update_status(plan_id: int, status: str):
        conn = get_db_connection()
        conn.execute("UPDATE assessment_plans SET status = ? WHERE id = ?", (status, plan_id))
        conn.commit()
        conn.close()

    @staticmethod
    def add_plan(phase_name: str, target_ip: str, recommended_action: str, rationale: str, coverage_gap: str = None):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO assessment_plans (phase_name, target_ip, recommended_action, rationale, coverage_gap, status)
            VALUES (?, ?, ?, ?, ?, 'PENDING')
        """, (phase_name, target_ip, recommended_action, rationale, coverage_gap))
        conn.commit()
        last_id = cur.lastrowid
        conn.close()
        return last_id
