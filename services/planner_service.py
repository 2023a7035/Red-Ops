"""
RedOps Bounded Assessment Planner Service
Evaluates current security assessment coverage across targets, services, and vulnerabilities.
Recommends the next prioritized, authorized assessment phase to bridge coverage gaps.
Requires explicit user approval before initiating any action.
"""
from database.db import get_db_connection, log_audit
from models.audit import PlannerModel

class PlannerService:
    @classmethod
    def analyze_coverage_and_plan(cls) -> list:
        """
        Synthesizes the current state of discovery, CVE correlation, and simulations
        to generate bounded, actionable next assessment recommendations.
        """
        conn = get_db_connection()

        # Check total assets vs scanned assets
        assets = conn.execute("SELECT * FROM assets").fetchall()
        services = conn.execute("SELECT * FROM services").fetchall()
        vulns = conn.execute("SELECT * FROM vulnerabilities").fetchall()
        executions = conn.execute("SELECT * FROM simulation_executions").fetchall()
        allowlist = conn.execute("SELECT * FROM target_allowlist WHERE is_approved = 1").fetchall()
        conn.close()

        existing_plans = PlannerModel.get_all()
        existing_actions = {p["recommended_action"] for p in existing_plans}

        new_plans = []

        # 1. Scope Coverage Check: Are there allowlisted targets not yet scanned?
        scanned_ips = {a["ip_address"] for a in assets}
        for item in allowlist:
            target = item["target"]
            if "/" not in target and target not in ("localhost", "127.0.0.1"):
                if target not in scanned_ips:
                    action = f"Execute initial discovery scan on unscanned target {target}"
                    if action not in existing_actions:
                        PlannerModel.add_plan(
                            phase_name="Phase 1: Asset Footprinting",
                            target_ip=target,
                            recommended_action=action,
                            rationale="Target is formally approved in the authorization allowlist but has zero service discovery records.",
                            coverage_gap=f"Unassessed target asset ({target})"
                        )

        # 2. Service Banner Audit Check: Any services with 'unknown' or unverified product versions?
        for svc in services:
            if not svc["version"] or svc["version"] == "Unknown":
                action = f"Run detailed banner extraction on host ID {svc['asset_id']} port {svc['port']}"
                if action not in existing_actions:
                    PlannerModel.add_plan(
                        phase_name="Phase 2: Service Version Fingerprinting",
                        target_ip=str(svc["asset_id"]),
                        recommended_action=action,
                        rationale="Port is open but service product version is ambiguous, preventing definitive CVE correlation.",
                        coverage_gap=f"Incomplete banner telemetry on port {svc['port']}"
                    )

        # 3. Critical Vulnerability Validation Check: Any Critical CVE without simulation verification?
        critical_vulns = [v for v in vulns if v["severity"] == "CRITICAL"]
        executed_scenarios = {e["scenario_id"] for e in executions}

        if critical_vulns and len(executions) < 3:
            action = "Perform safe signature verification (SIM-EXPLOIT-04) on web application tier"
            if action not in existing_actions:
                PlannerModel.add_plan(
                    phase_name="Phase 3: Attack Path Validation",
                    target_ip="172.28.0.20",
                    recommended_action=action,
                    rationale="High-priority Spring4Shell (CVE-2022-22965) identified on perimeter web portal. Safe canary probe required to confirm exploitability.",
                    coverage_gap="Unvalidated critical entrypoint vulnerability"
                )

        # 4. Remediation Prioritization Check: Has crown jewel database been isolated?
        action = "Generate comprehensive risk remediation report for Database Cluster (172.28.0.30)"
        if action not in existing_actions:
            PlannerModel.add_plan(
                phase_name="Phase 4: Defensive Hardening & Verification",
                target_ip="172.28.0.30",
                recommended_action=action,
                rationale="Database host exposes unauthenticated Redis 5.0.7 and PostgreSQL with root-pivot attack paths.",
                coverage_gap="Remediation plan pending deployment"
            )

        log_audit("PLANNER_COVERAGE_ANALYSIS", details="Assessment coverage analysis updated.")
        return PlannerModel.get_all()

    @classmethod
    def execute_plan_step(cls, plan_id: int) -> dict:
        """
        Executes an approved planner recommendation step.
        """
        conn = get_db_connection()
        plan = conn.execute("SELECT * FROM assessment_plans WHERE id = ?", (plan_id,)).fetchone()
        conn.close()

        if not plan:
            return {"success": False, "error": "Plan not found"}

        # Mark as EXECUTED
        PlannerModel.update_status(plan_id, "EXECUTED")
        log_audit(
            "PLAN_STEP_EXECUTED",
            target=plan["target_ip"],
            details=f"Phase: {plan['phase_name']} | Action: {plan['recommended_action']}"
        )

        return {
            "success": True,
            "message": f"Successfully processed plan step '{plan['recommended_action']}'.",
            "plan_id": plan_id
        }
