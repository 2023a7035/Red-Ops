"""
Runtime Verification Script
Starts a test client against the complete RedOps Flask application and validates every route.
"""
from app import create_app

def verify_all():
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    routes = [
        ("/", "Executive SOC Command Center"),
        ("/discovery", "Authorized Asset & Service Discovery"),
        ("/vulnerabilities", "Vulnerability Correlation & CVE Mapping"),
        ("/attack-graph", "Graph-Based Attack-Path Analysis"),
        ("/ai-reasoning", "AI-Based Threat Reasoning Engine"),
        ("/simulation", "Controlled Attack Simulation Engine"),
        ("/planner", "Bounded Assessment Planner"),
        ("/reports", "Security Reports & Compliance Deliverables"),
        ("/settings", "Target Scope & System Governance"),
        ("/api/dashboard/stats", "total_assets"),
        ("/api/discovery/assets", "assets"),
        ("/api/vulnerabilities", "vulnerabilities"),
        ("/api/graph/elements", "elements"),
        ("/api/graph/paths", "paths"),
        ("/api/ai/latest", "analysis"),
        ("/api/simulation/scenarios", "scenarios"),
        ("/api/simulation/executions", "executions"),
        ("/api/planner/steps", "plans"),
        ("/api/settings/allowlist", "allowlist"),
        ("/api/reports/download/pdf", "%PDF"),
        ("/api/reports/download/csv-vulns", "CVE ID"),
        ("/api/reports/download/csv-assets", "IP Address"),
    ]

    print("=" * 60)
    print(" [VERIFICATION] Testing all RedOps platform routes...")
    print("=" * 60)

    all_passed = True
    for route, expected in routes:
        resp = client.get(route)
        is_ok = resp.status_code == 200
        contains_content = expected.encode() in resp.data
        status_str = "PASS" if (is_ok and contains_content) else "FAIL"
        if not (is_ok and contains_content):
            all_passed = False
        print(f"[{status_str}] Route: {route:<32} Status: {resp.status_code}")

    print("=" * 60)
    if all_passed:
        print(" [SUCCESS] ALL 22 ROUTES VERIFIED WITH ZERO ERRORS!")
    else:
        print(" [ERROR] Some routes failed verification.")
    print("=" * 60)
    return all_passed

if __name__ == "__main__":
    verify_all()
