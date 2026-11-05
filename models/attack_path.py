"""
Attack Path Model
Handles storage and retrieval of synthesized attack paths and graph metrics.
"""
import json
from database.db import get_db_connection

class AttackPathModel:
    @staticmethod
    def get_all():
        conn = get_db_connection()
        paths = conn.execute("SELECT * FROM attack_paths ORDER BY risk_score DESC").fetchall()
        for p in paths:
            try:
                p["path_nodes"] = json.loads(p["path_nodes_json"])
            except Exception:
                p["path_nodes"] = []
            try:
                p["mitre_tactics"] = json.loads(p["mitre_tactics_json"])
            except Exception:
                p["mitre_tactics"] = []
        conn.close()
        return paths

    @staticmethod
    def get_by_id(path_id: int):
        conn = get_db_connection()
        path = conn.execute("SELECT * FROM attack_paths WHERE id = ?", (path_id,)).fetchone()
        if path:
            try:
                path["path_nodes"] = json.loads(path["path_nodes_json"])
            except Exception:
                path["path_nodes"] = []
            try:
                path["mitre_tactics"] = json.loads(path["mitre_tactics_json"])
            except Exception:
                path["mitre_tactics"] = []
        conn.close()
        return path

    @staticmethod
    def insert_path(name: str, source_node: str, target_node: str, path_nodes: list,
                    risk_score: float, severity: str, description: str, mitre_tactics: list,
                    is_exploited: int = 0):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO attack_paths (name, source_node, target_node, path_nodes_json, risk_score, severity, description, mitre_tactics_json, is_exploited_simulated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, source_node, target_node, json.dumps(path_nodes), risk_score, severity, description, json.dumps(mitre_tactics), is_exploited))
        conn.commit()
        path_id = cur.lastrowid
        conn.close()
        return path_id
