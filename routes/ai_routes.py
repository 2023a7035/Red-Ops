"""
AI Reasoning Routes
Handles LLM-based attack path analysis, threat narratives, and mitigation advice.
"""
from flask import Blueprint, render_template, request, jsonify
from services.llm_service import LLMService
from database.db import get_db_connection
from models.attack_path import AttackPathModel
from config import Config

ai_bp = Blueprint("ai", __name__)

@ai_bp.route("/ai-reasoning")
def ai_page():
    paths = AttackPathModel.get_all()
    conn = get_db_connection()
    latest_ai = conn.execute("SELECT * FROM ai_reasoning ORDER BY created_at DESC LIMIT 1").fetchone()
    conn.close()

    parsed_evidence = {}
    parsed_risks = []
    parsed_recommendations = []
    if latest_ai:
        try:
            parsed_evidence = latest_ai["graph_evidence_json"]
        except Exception:
            pass
        try:
            parsed_risks = latest_ai["risk_factors_json"]
        except Exception:
            pass
        try:
            parsed_recommendations = latest_ai["defensive_recommendations_json"]
        except Exception:
            pass

    return render_template(
        "ai_reasoning.html",
        active_page="ai-reasoning",
        paths=paths,
        latest_ai=latest_ai,
        evidence=parsed_evidence,
        risks=parsed_risks,
        recommendations=parsed_recommendations,
        provider=Config.AI_PROVIDER
    )

@ai_bp.route("/api/ai/latest")
def get_latest_analysis():
    conn = get_db_connection()
    record = conn.execute("SELECT * FROM ai_reasoning ORDER BY created_at DESC LIMIT 1").fetchone()
    conn.close()
    return jsonify({"success": True, "analysis": record})

@ai_bp.route("/api/ai/analyze", methods=["POST"])
def analyze_path():
    data = request.get_json() or {}
    path_id = data.get("path_id")
    target_asset_id = data.get("target_asset_id")

    analysis = LLMService.analyze_path(path_id=path_id, target_asset_id=target_asset_id)
    return jsonify({"success": True, "analysis": analysis})
