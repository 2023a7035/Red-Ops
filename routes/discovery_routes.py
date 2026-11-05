"""
Discovery Routes
Handles network asset discovery, Nmap and socket scans, and scan history.
"""
from flask import Blueprint, render_template, request, jsonify
from services.discovery_service import DiscoveryService
from models.asset import AssetModel
from models.audit import AllowlistModel
from database.db import get_db_connection

discovery_bp = Blueprint("discovery", __name__)

@discovery_bp.route("/discovery")
def discovery_page():
    allowlist = AllowlistModel.get_all()
    return render_template("discovery.html", active_page="discovery", allowlist=allowlist)

@discovery_bp.route("/api/discovery/scan", methods=["POST"])
def run_scan():
    data = request.get_json() or {}
    target = data.get("target", "").strip()
    scan_profile = data.get("profile", "quick")

    if not target:
        return jsonify({"success": False, "error": "Target specification is required."}), 400

    results = DiscoveryService.execute_scan(target=target, scan_profile=scan_profile)
    return jsonify(results)

@discovery_bp.route("/api/discovery/assets")
def get_discovered_assets():
    assets = AssetModel.get_all()
    return jsonify({"success": True, "assets": assets})

@discovery_bp.route("/api/discovery/history")
def get_scan_history():
    conn = get_db_connection()
    scans = conn.execute("SELECT * FROM scan_history ORDER BY started_at DESC LIMIT 20").fetchall()
    conn.close()
    return jsonify({"success": True, "scans": scans})
