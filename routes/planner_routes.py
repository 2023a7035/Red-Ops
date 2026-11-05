"""
Assessment Planner Routes
Serves coverage gap evaluations and handles approval and execution of next assessment phases.
"""
from flask import Blueprint, render_template, request, jsonify
from services.planner_service import PlannerService
from models.audit import PlannerModel

planner_bp = Blueprint("planner", __name__)

@planner_bp.route("/planner")
def planner_page():
    plans = PlannerService.analyze_coverage_and_plan()
    return render_template("planner.html", active_page="planner", plans=plans)

@planner_bp.route("/api/planner/steps")
def get_planner_steps():
    plans = PlannerService.analyze_coverage_and_plan()
    return jsonify({"success": True, "plans": plans})

@planner_bp.route("/api/planner/execute/<int:plan_id>", methods=["POST"])
def execute_plan_step(plan_id):
    result = PlannerService.execute_plan_step(plan_id)
    return jsonify(result)
