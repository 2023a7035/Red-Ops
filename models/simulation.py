"""
Simulation Model
Manages controlled simulation scenarios, approval workflows, and execution logs.
"""
from database.db import get_db_connection

class SimulationModel:
    @staticmethod
    def get_scenarios():
        conn = get_db_connection()
        scenarios = conn.execute("SELECT * FROM simulation_scenarios ORDER BY id ASC").fetchall()
        conn.close()
        return scenarios

    @staticmethod
    def get_scenario_by_id(scenario_id: int):
        conn = get_db_connection()
        scenario = conn.execute("SELECT * FROM simulation_scenarios WHERE id = ?", (scenario_id,)).fetchone()
        conn.close()
        return scenario

    @staticmethod
    def get_scenario_by_code(code: str):
        conn = get_db_connection()
        scenario = conn.execute("SELECT * FROM simulation_scenarios WHERE code = ?", (code,)).fetchone()
        conn.close()
        return scenario

    @staticmethod
    def get_executions():
        conn = get_db_connection()
        executions = conn.execute("""
            SELECT e.*, s.name AS scenario_name, s.code AS scenario_code,
                   s.mitre_technique_id, s.mitre_technique_name, s.mitre_tactic
            FROM simulation_executions e
            JOIN simulation_scenarios s ON e.scenario_id = s.id
            ORDER BY e.executed_at DESC
        """).fetchall()
        conn.close()
        return executions

    @staticmethod
    def create_execution(scenario_id: int, target_ip: str, target_port: int,
                         user_approved_by: str, status: str = "PENDING_APPROVAL"):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO simulation_executions (scenario_id, target_ip, target_port, status, user_approved_by)
            VALUES (?, ?, ?, ?, ?)
        """, (scenario_id, target_ip, target_port, status, user_approved_by))
        conn.commit()
        exec_id = cur.lastrowid
        conn.close()
        return exec_id

    @staticmethod
    def update_execution(exec_id: int, status: str, logs: str, findings: str, mitre_mapped: str):
        conn = get_db_connection()
        conn.execute("""
            UPDATE simulation_executions
            SET status = ?, logs = ?, findings = ?, mitre_mapped = ?
            WHERE id = ?
        """, (status, logs, findings, mitre_mapped, exec_id))
        conn.commit()
        conn.close()
