"""
Test Flask API Endpoints
Integration test suite ensuring all REST endpoints return valid responses.
"""
import pytest
import json
from app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_dashboard_page(client):
    rv = client.get("/")
    assert rv.status_code == 200
    assert b"Executive SOC Command Center" in rv.data

def test_dashboard_stats_api(client):
    rv = client.get("/api/dashboard/stats")
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert data["success"] is True
    assert "metrics" in data
    assert data["metrics"]["total_assets"] >= 4

def test_discovery_page(client):
    rv = client.get("/discovery")
    assert rv.status_code == 200
    assert b"Asset &amp; Service Discovery" in rv.data or b"Asset & Service Discovery" in rv.data

def test_vulnerabilities_api(client):
    rv = client.get("/api/vulnerabilities")
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert data["success"] is True
    assert len(data["vulnerabilities"]) > 0

def test_graph_elements_api(client):
    rv = client.get("/api/graph/elements")
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert data["success"] is True
    assert len(data["elements"]) > 0

def test_attack_paths_api(client):
    rv = client.get("/api/graph/paths")
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert data["success"] is True
    assert len(data["paths"]) > 0

def test_ai_reasoning_api(client):
    rv = client.get("/api/ai/latest")
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert data["success"] is True

def test_simulation_scenarios_api(client):
    rv = client.get("/api/simulation/scenarios")
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert data["success"] is True
    assert len(data["scenarios"]) >= 5

def test_unauthorized_scan_rejection(client):
    rv = client.post("/api/discovery/scan", json={"target": "8.8.8.8", "profile": "quick"})
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert data["success"] is False
    assert "POLICY" in data["error"] or "VIOLATION" in data["error"]

def test_reports_page(client):
    rv = client.get("/reports")
    assert rv.status_code == 200
    assert b"Security Reports &amp; Compliance Deliverables" in rv.data or b"Security Reports & Compliance Deliverables" in rv.data
