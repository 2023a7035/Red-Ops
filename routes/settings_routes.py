"""
Settings and Allowlist Routes
Manages laboratory targets, scope policies, and demonstration seed datasets.
"""
from flask import Blueprint, render_template, request, jsonify
from models.audit import AllowlistModel
from database.seed_data import seed_database
from database.db import log_audit, get_db_connection

settings_bp = Blueprint("settings", __name__)

@settings_bp.route("/settings")
def settings_page():
    allowlist = AllowlistModel.get_all()
    conn = get_db_connection()
    audit_logs = conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 40").fetchall()
    conn.close()
    return render_template("settings.html", active_page="settings", allowlist=allowlist, audit_logs=audit_logs)

@settings_bp.route("/api/settings/allowlist", methods=["GET"])
def get_allowlist():
    targets = AllowlistModel.get_all()
    return jsonify({"success": True, "allowlist": targets})

@settings_bp.route("/api/settings/allowlist/add", methods=["POST"])
def add_allowlist_target():
    data = request.get_json() or {}
    target = data.get("target", "").strip()
    label = data.get("label", "Laboratory Host").strip()
    description = data.get("description", "Authorized assessment target").strip()

    if not target:
        return jsonify({"success": False, "error": "Target IP/subnet is required."}), 400

    target_id = AllowlistModel.add(target=target, label=label, description=description)
    log_audit("ALLOWLIST_TARGET_ADDED", target=target, details=f"Label: {label}")
    return jsonify({"success": True, "target_id": target_id, "target": target})

@settings_bp.route("/api/settings/allowlist/<int:target_id>", methods=["DELETE"])
def delete_allowlist_target(target_id):
    AllowlistModel.delete(target_id)
    log_audit("ALLOWLIST_TARGET_REMOVED", details=f"Target ID {target_id} removed from scope.")
    return jsonify({"success": True, "message": "Target removed successfully."})

@settings_bp.route("/api/settings/reset-seed", methods=["POST"])
def reset_seed_data():
    seed_database(force_refresh=True)
    log_audit("LAB_ENVIRONMENT_RESET", details="Restored full baseline enterprise laboratory dataset.")
    return jsonify({"success": True, "message": "Laboratory database reset successfully to baseline enterprise dataset."})
