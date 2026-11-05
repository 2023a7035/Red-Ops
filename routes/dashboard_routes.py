"""
Dashboard Routes
Renders the executive command center and serves real-time security posture metrics.
"""
from flask import Blueprint, render_template, jsonify
from database.db import get_db_connection
from models.vulnerability import VulnerabilityModel
from models.asset import AssetModel
from models.audit import AuditModel

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/")
def index():
    return render_template("dashboard.html", active_page="dashboard")

@dashboard_bp.route("/api/dashboard/stats")
def get_stats():
    conn = get_db_connection()

    # Asset counts
    asset_count = conn.execute("SELECT COUNT(*) AS count FROM assets").fetchone()["count"]
    service_count = conn.execute("SELECT COUNT(*) AS count FROM services").fetchone()["count"]

    # Vulnerability counts
    vuln_counts = VulnerabilityModel.get_severity_counts()

    # Attack paths count
    path_count = conn.execute("SELECT COUNT(*) AS count FROM attack_paths").fetchone()["count"]

    # Simulation executions count
    sim_count = conn.execute("SELECT COUNT(*) AS count FROM simulation_executions WHERE status = 'COMPLETED'").fetchone()["count"]

    # Scan history count
    scan_count = conn.execute("SELECT COUNT(*) AS count FROM scan_history WHERE status = 'COMPLETED'").fetchone()["count"]

    # Recent Audit Activities
    recent_activities = AuditModel.get_logs(limit=8)

    # Top vulnerable assets
    top_assets = conn.execute("""
        SELECT a.ip_address, a.hostname, a.criticality, a.role,
               COUNT(v.id) AS vuln_count,
               SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
               SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) AS high_count
        FROM assets a
        LEFT JOIN services s ON a.id = s.asset_id
        LEFT JOIN vulnerabilities v ON s.id = v.service_id
        GROUP BY a.id
        ORDER BY critical_count DESC, high_count DESC, vuln_count DESC
        LIMIT 5
    """).fetchall()

    conn.close()

    # Calculate overall security posture score (0 - 100, 100 = Hardened, 0 = High Compromise Risk)
    crit = vuln_counts.get("critical", 0) or 0
    high = vuln_counts.get("high", 0) or 0
    med = vuln_counts.get("medium", 0) or 0
    risk_deduction = (crit * 18) + (high * 8) + (med * 3)
    posture_score = max(12, min(95, 100 - risk_deduction))

    posture_status = "CRITICAL RISK" if posture_score < 40 else "ELEVATED RISK" if posture_score < 70 else "NOMINAL"

    return jsonify({
        "success": True,
        "metrics": {
            "total_assets": asset_count,
            "active_hosts": asset_count,
            "open_ports": service_count,
            "total_vulnerabilities": vuln_counts.get("total", 0) or 0,
            "critical_vulns": crit,
            "high_vulns": high,
            "medium_vulns": med,
            "low_vulns": vuln_counts.get("low", 0) or 0,
            "attack_paths": path_count,
            "completed_simulations": sim_count,
            "completed_scans": scan_count,
            "posture_score": posture_score,
            "posture_status": posture_status
        },
        "top_assets": top_assets,
        "recent_activities": recent_activities
    })
