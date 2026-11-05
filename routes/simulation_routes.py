"""
Controlled Simulation Routes
Handles safe, non-destructive red team simulations mapped to MITRE ATT&CK.
Enforces human authorization and allowlist scope validation.
"""
from flask import Blueprint, render_template, request, jsonify
from services.simulation_service import SimulationService
from models.simulation import SimulationModel
from models.asset import AssetModel

simulation_bp = Blueprint("simulation", __name__)

@simulation_bp.route("/simulation")
def simulation_page():
    scenarios = SimulationModel.get_scenarios()
    executions = SimulationModel.get_executions()
    assets = AssetModel.get_all()
    return render_template(
        "simulation.html",
        active_page="simulation",
        scenarios=scenarios,
        executions=executions,
        assets=assets
    )

@simulation_bp.route("/api/simulation/scenarios")
def get_scenarios():
    scenarios = SimulationModel.get_scenarios()
    return jsonify({"success": True, "scenarios": scenarios})

@simulation_bp.route("/api/simulation/execute", methods=["POST"])
def execute_simulation():
    data = request.get_json() or {}
    scenario_id = data.get("scenario_id")
    target_ip = data.get("target_ip", "").strip()
    target_port = int(data.get("target_port", 80))
    approved_by = data.get("approved_by", "security_operator").strip()

    if not scenario_id or not target_ip:
        return jsonify({"success": False, "error": "Scenario ID and Target IP are required."}), 400

    result = SimulationService.execute_scenario(
        scenario_id=int(scenario_id),
        target_ip=target_ip,
        target_port=target_port,
        approved_by=approved_by
    )
    return jsonify(result)

@simulation_bp.route("/api/simulation/executions")
def get_executions():
    executions = SimulationModel.get_executions()
    return jsonify({"success": True, "executions": executions})
