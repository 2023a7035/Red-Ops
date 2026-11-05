"""
RedOps Database Interface
Handles SQLite database connection, table schemas, initialization, and query helpers.
"""
import sqlite3
import os
import json
from datetime import datetime
from config import Config

def dict_factory(cursor, row):
    """Convert sqlite rows to standard Python dictionaries."""
    fields = [column[0] for column in cursor.description]
    return {key: value for key, value in zip(fields, row)}

def get_db_connection():
    """Returns a connection to the SQLite database with row factory enabled."""
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = dict_factory
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """Initializes all required tables in the database if they do not exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Target Allowlist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS target_allowlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT UNIQUE NOT NULL,
            label TEXT,
            description TEXT,
            is_approved INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 2. Assets (Hosts)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            hostname TEXT,
            os_name TEXT,
            os_version TEXT,
            status TEXT DEFAULT 'active',
            mac_address TEXT,
            criticality TEXT DEFAULT 'MEDIUM', -- LOW, MEDIUM, HIGH, CRITICAL
            role TEXT DEFAULT 'Host',          -- Gateway, Web Server, Database, DC, Workstation
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Services
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'tcp',
            service_name TEXT NOT NULL,
            product TEXT,
            version TEXT,
            state TEXT DEFAULT 'open',
            banner TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
            UNIQUE(asset_id, port, protocol)
        )
    """)

    # 4. Vulnerabilities
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            title TEXT,
            description TEXT,
            cvss_score REAL DEFAULT 0.0,
            severity TEXT DEFAULT 'MEDIUM', -- LOW, MEDIUM, HIGH, CRITICAL
            affected_versions TEXT,
            remediation TEXT,
            confidence TEXT DEFAULT 'CONFIRMED', -- CONFIRMED, POTENTIAL
            references_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
        )
    """)

    # 5. Attack Paths
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            source_node TEXT NOT NULL,
            target_node TEXT NOT NULL,
            path_nodes_json TEXT NOT NULL,
            risk_score REAL DEFAULT 0.0,
            severity TEXT DEFAULT 'HIGH',
            description TEXT,
            mitre_tactics_json TEXT,
            is_exploited_simulated INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 6. AI Reasoning Records
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ai_reasoning (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_asset_id INTEGER,
            attack_path_id INTEGER,
            analysis_type TEXT DEFAULT 'attack_path_analysis',
            ai_provider TEXT DEFAULT 'local',
            reasoning_text TEXT NOT NULL,
            graph_evidence_json TEXT,
            risk_factors_json TEXT,
            defensive_recommendations_json TEXT,
            limitations_text TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_asset_id) REFERENCES assets(id) ON DELETE SET NULL,
            FOREIGN KEY (attack_path_id) REFERENCES attack_paths(id) ON DELETE SET NULL
        )
    """)

    # 7. Simulation Scenarios
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS simulation_scenarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            mitre_technique_id TEXT,
            mitre_technique_name TEXT,
            mitre_tactic TEXT,
            severity TEXT DEFAULT 'MEDIUM',
            safety_notes TEXT,
            requires_approval INTEGER DEFAULT 1
        )
    """)

    # 8. Simulation Executions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS simulation_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario_id INTEGER NOT NULL,
            target_ip TEXT NOT NULL,
            target_port INTEGER,
            status TEXT DEFAULT 'PENDING_APPROVAL', -- PENDING_APPROVAL, RUNNING, COMPLETED, FAILED, BLOCKED
            user_approved_by TEXT,
            logs TEXT,
            findings TEXT,
            mitre_mapped TEXT,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scenario_id) REFERENCES simulation_scenarios(id) ON DELETE CASCADE
        )
    """)

    # 9. Bounded Assessment Plans
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assessment_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phase_name TEXT NOT NULL,
            target_ip TEXT,
            recommended_action TEXT NOT NULL,
            rationale TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING', -- PENDING, APPROVED, EXECUTED, SKIPPED
            coverage_gap TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 10. Audit Logs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            user_id TEXT DEFAULT 'admin_analyst',
            target TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 11. Scan History
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_type TEXT DEFAULT 'quick_service_scan',
            status TEXT DEFAULT 'COMPLETED', -- RUNNING, COMPLETED, FAILED, BLOCKED
            hosts_discovered INTEGER DEFAULT 0,
            ports_found INTEGER DEFAULT 0,
            raw_output TEXT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

def log_audit(action: str, target: str = None, details: str = None, user_id: str = "security_lead"):
    """Helper to log security assessment activity into the audit trail."""
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO audit_logs (action, user_id, target, details) VALUES (?, ?, ?, ?)",
            (action, user_id, target, details)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[AUDIT_ERROR] Failed to log audit event: {e}")
