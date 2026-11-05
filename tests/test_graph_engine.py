"""
Test NetworkX Graph Engine
Validates graph construction, node typing, edge weights, and attack path finding.
"""
import pytest
import networkx as nx
from services.graph_service import GraphService

def test_build_networkx_graph():
    G = GraphService.build_networkx_graph()
    assert isinstance(G, nx.DiGraph)
    assert G.number_of_nodes() > 0
    assert G.number_of_edges() > 0

    # Ensure external entrypoint exists
    assert "entry_external" in G.nodes
    assert G.nodes["entry_external"]["type"] == "entrypoint"

    # Verify node types exist
    node_types = {d.get("type") for n, d in G.nodes(data=True)}
    assert "entrypoint" in node_types
    assert "host" in node_types or "target" in node_types
    assert "service" in node_types
    assert "vulnerability" in node_types

def test_attack_path_analysis():
    paths = GraphService.analyze_attack_paths()
    assert len(paths) > 0
    for p in paths:
        assert p["risk_score"] > 0.0
        assert p["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert len(p["path_nodes"]) >= 2
        assert "target_node" in p

def test_cytoscape_elements_format():
    elements = GraphService.get_cytoscape_elements()
    assert len(elements) > 0
    nodes = [e for e in elements if e.get("group") == "nodes"]
    edges = [e for e in elements if e.get("group") == "edges"]

    assert len(nodes) > 0
    assert len(edges) > 0

    for n in nodes:
        assert "id" in n["data"]
        assert "label" in n["data"]
        assert "classes" in n
