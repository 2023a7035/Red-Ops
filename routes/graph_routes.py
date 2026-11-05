"""
Attack Graph Routes
Renders the interactive Cytoscape.js attack path canvas and supplies NetworkX graph data.
"""
from flask import Blueprint, render_template, jsonify
from services.graph_service import GraphService
from models.attack_path import AttackPathModel

graph_bp = Blueprint("graph", __name__)

@graph_bp.route("/attack-graph")
def graph_page():
    paths = AttackPathModel.get_all()
    return render_template("attack_graph.html", active_page="attack-graph", paths=paths)

@graph_bp.route("/api/graph/elements")
def get_graph_elements():
    """Returns elements ready for Cytoscape.js initialization."""
    elements = GraphService.get_cytoscape_elements()
    return jsonify({"success": True, "elements": elements})

@graph_bp.route("/api/graph/paths")
def get_attack_paths():
    """Returns synthesized attack paths analyzed from the graph."""
    paths = GraphService.analyze_attack_paths()
    return jsonify({"success": True, "paths": paths})
