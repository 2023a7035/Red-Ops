"""
Reporting Routes
Manages generation and downloading of PDF and CSV assessment reports.
"""
from flask import Blueprint, render_template, send_file, jsonify
from services.reporting_service import ReportingService
from database.db import get_db_connection

reporting_bp = Blueprint("reporting", __name__)

@reporting_bp.route("/reports")
def reports_page():
    conn = get_db_connection()
    assets_count = conn.execute("SELECT COUNT(*) AS c FROM assets").fetchone()["c"]
    vulns_count = conn.execute("SELECT COUNT(*) AS c FROM vulnerabilities").fetchone()["c"]
    paths_count = conn.execute("SELECT COUNT(*) AS c FROM attack_paths").fetchone()["c"]
    sims_count = conn.execute("SELECT COUNT(*) AS c FROM simulation_executions").fetchone()["c"]
    conn.close()
    return render_template(
        "reports.html",
        active_page="reports",
        assets_count=assets_count,
        vulns_count=vulns_count,
        paths_count=paths_count,
        sims_count=sims_count
    )

@reporting_bp.route("/api/reports/download/pdf")
def download_pdf():
    pdf_path = ReportingService.generate_pdf_report()
    return send_file(pdf_path, as_attachment=True, download_name="RedOps_Security_Assessment_Report.pdf")

@reporting_bp.route("/api/reports/download/csv-vulns")
def download_csv_vulns():
    csv_path = ReportingService.generate_csv_vulnerabilities()
    return send_file(csv_path, as_attachment=True, download_name="RedOps_Vulnerabilities.csv")

@reporting_bp.route("/api/reports/download/csv-assets")
def download_csv_assets():
    csv_path = ReportingService.generate_csv_assets()
    return send_file(csv_path, as_attachment=True, download_name="RedOps_Assets_Inventory.csv")
