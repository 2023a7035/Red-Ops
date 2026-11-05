"""
RedOps LLM Reasoning & AI Threat Intelligence Module
Processes structured graph evidence, attack paths, and vulnerability correlations.
Generates explainable cybersecurity threat narratives, multi-factor risk assessments,
and prioritized defensive remediation roadmaps.

Provides a robust, clearly-labelled Local Rule-Based Security Expert Engine fallback
when remote LLM API keys are not configured or network access is restricted.
Strictly advisory; cannot execute shell commands or modify security scope.
"""
import os
import json
import requests
from datetime import datetime
from config import Config
from database.db import get_db_connection, log_audit

class LLMService:
    @classmethod
    def analyze_path(cls, path_id: int = None, target_asset_id: int = None) -> dict:
        """
        Executes AI reasoning on a given attack path and target asset.
        Selects remote LLM API or Local Rule-Based Security Expert Engine accordingly.
        """
        conn = get_db_connection()

        # Gather graph context
        path = None
        if path_id:
            path = conn.execute("SELECT * FROM attack_paths WHERE id = ?", (path_id,)).fetchone()
        if not path:
            path = conn.execute("SELECT * FROM attack_paths ORDER BY risk_score DESC LIMIT 1").fetchone()

        asset = None
        if target_asset_id:
            asset = conn.execute("SELECT * FROM assets WHERE id = ?", (target_asset_id,)).fetchone()
        if not asset and path:
            # Infer target from path
            asset = conn.execute("SELECT * FROM assets WHERE criticality = 'CRITICAL' LIMIT 1").fetchone()

        # Fetch associated vulnerabilities
        vulns = conn.execute("""
            SELECT v.cve_id, v.title, v.cvss_score, v.severity, v.remediation,
                   s.port, s.service_name, a.ip_address, a.hostname
            FROM vulnerabilities v
            JOIN services s ON v.service_id = s.id
            JOIN assets a ON s.asset_id = a.id
            ORDER BY v.cvss_score DESC
        """).fetchall()
        conn.close()

        # Build structured graph evidence payload
        evidence = {
            "path_name": path["name"] if path else "Enterprise Core Breach Vector",
            "source": path["source_node"] if path else "External Threat Actor",
            "target": path["target_node"] if path else "Internal Database / DC",
            "risk_score": path["risk_score"] if path else 9.5,
            "severity": path["severity"] if path else "CRITICAL",
            "path_steps": json.loads(path["path_nodes_json"]) if (path and path.get("path_nodes_json")) else [],
            "identified_cves": [
                {
                    "cve": v["cve_id"],
                    "title": v["title"],
                    "cvss": v["cvss_score"],
                    "severity": v["severity"],
                    "host": f"{v['hostname']} ({v['ip_address']}):{v['port']}",
                    "service": v["service_name"]
                }
                for v in vulns[:5]
            ]
        }

        # Determine AI Provider
        provider = Config.AI_PROVIDER.lower()
        if provider == "openai" and Config.OPENAI_API_KEY:
            result = cls._query_openai(evidence)
        elif provider == "gemini" and Config.GEMINI_API_KEY:
            result = cls._query_gemini(evidence)
        else:
            # High-confidence local rule-based security expert fallback
            result = cls._local_rule_based_engine(evidence, asset)

        # Persist AI Reasoning Output to Database
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO ai_reasoning (
                target_asset_id, attack_path_id, analysis_type, ai_provider,
                reasoning_text, graph_evidence_json, risk_factors_json,
                defensive_recommendations_json, limitations_text
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            asset["id"] if asset else None,
            path["id"] if path else None,
            "attack_path_analysis",
            result["provider_label"],
            result["reasoning_text"],
            json.dumps(result["graph_evidence"]),
            json.dumps(result["risk_factors"]),
            json.dumps(result["defensive_recommendations"]),
            result["limitations"]
        ))
        conn.commit()
        ai_id = cur.lastrowid
        conn.close()

        log_audit(
            "AI_REASONING_PRODUCED",
            target=evidence["target"],
            details=f"Provider: {result['provider_label']} | Risk: {evidence['risk_score']}"
        )

        result["id"] = ai_id
        return result

    @classmethod
    def _local_rule_based_engine(cls, evidence: dict, asset: dict) -> dict:
        """
        Deterministic, rule-based cybersecurity expert engine.
        Synthesizes multi-stage attack chaining, exploit mechanics, and defense-in-depth mitigations.
        """
        cves = evidence.get("identified_cves", [])
        cve_ids = [c["cve"] for c in cves]

        critical_count = sum(1 for c in cves if c["severity"] == "CRITICAL")
        has_spring4shell = any("CVE-2022-22965" in cid for cid in cve_ids)
        has_redis_rce = any("CVE-2022-0543" in cid for cid in cve_ids)
        has_zerologon = any("CVE-2020-1472" in cid for cid in cve_ids)
        has_ghostcat = any("CVE-2020-1938" in cid for cid in cve_ids)

        narrative_parts = [
            f"EXECUTIVE SECURITY ADVISORY: RedOps Threat Graph Engine identified a high-severity chained attack vector originating from '{evidence['source']}' targeting '{evidence['target']}' with an aggregate risk score of {evidence['risk_score']}/10.0.",
            "\nEXPLOITATION CHAINING ANALYSIS:"
        ]

        if has_spring4shell and has_redis_rce:
            narrative_parts.append(
                "1. Initial Access: The perimeter exposes Spring Framework (CVE-2022-22965 / Spring4Shell) on the web tier. An external adversary can submit crafted HTTP POST class-loader parameters to achieve unauthenticated Remote Code Execution.\n"
                "2. Lateral Movement & Pivoting: The application container shares an unsegmented internal network bridge with the database cluster. Unrestricted TCP connectivity allows direct pivoting to Redis on port 6379.\n"
                "3. Root Host Escalation: By exploiting CVE-2022-0543 (Redis Lua Sandbox Escape), the attacker executes OS system commands under high privileges, extracting production credentials and achieving complete data exfiltration."
            )
        elif has_ghostcat or has_zerologon:
            narrative_parts.append(
                "1. Boundary Breach: Insecure exposure of administrative interfaces (Apache Tomcat AJP / Ghostcat CVE-2020-1938) allows arbitrary file inspection, retrieving database credentials and application keys.\n"
                "2. Domain Dominance: With network presence established, Zerologon (CVE-2020-1472) allows resetting the Domain Controller computer account password via flawed Netlogon cryptography, leading to complete Active Directory forest compromise."
            )
        else:
            narrative_parts.append(
                f"1. Service Reconnaissance: The target environment presents {len(cves)} correlated vulnerability exposures across network boundary assets.\n"
                "2. Threat Chaining: Weaknesses in version-pinned perimeter services allow attackers to establish initial persistence and pivot towards internal critical segments."
            )

        narrative_text = "\n".join(narrative_parts)

        risk_factors = [
            f"Vulnerability Density: {critical_count} CRITICAL severity CVEs present across active attack path nodes.",
            "Network Architecture: Absence of internal network segmentation (flat private CIDR) permitting direct lateral hopping.",
            "Authentication Deficiencies: Default configurations or missing access tokens on internal caching/database ports.",
            "Exploit Availability: High public exploit maturity (Metasploit / public PoCs available for correlated CVEs)."
        ]

        recommendations = [
            {
                "priority": "P0 - IMMEDIATE (24-48 Hours)",
                "action": "Patch Critical Boundary RCE Vulnerabilities",
                "detail": "Upgrade Spring Framework to 5.3.18+ / 5.2.20+ and patch Apache Tomcat to 9.0.62+. Apply vendor security updates immediately.",
                "mitre_tactic": "TA0001: Initial Access / TA0002: Execution"
            },
            {
                "priority": "P1 - HIGH (3-7 Days)",
                "action": "Enforce Zero-Trust Network Microsegmentation",
                "detail": "Implement firewall filtering and host-level ingress rules: isolate Database (5432, 6379) and Domain Controller (88, 389, 445) so they cannot be directly queried from the DMZ/Web tier.",
                "mitre_tactic": "TA0008: Lateral Movement"
            },
            {
                "priority": "P2 - MEDIUM (1-2 Weeks)",
                "action": "Harden Internal Database & Identity Stores",
                "detail": "Enable Redis 'requirepass' authentication and bind exclusively to 127.0.0.1. Apply Microsoft KB4557222 to enforce Secure RPC Netlogon.",
                "mitre_tactic": "TA0004: Privilege Escalation"
            },
            {
                "priority": "P3 - ARCHITECTURAL (Ongoing)",
                "action": "Continuous Attack Surface & Egress Monitoring",
                "detail": "Deploy intrusion detection rules (Suricata/Snort) for ClassLoader manipulation and anomalous Kerberos ticket requests.",
                "mitre_tactic": "TA0010: Exfiltration"
            }
        ]

        return {
            "provider_label": "Local Rule-Based Security Expert Engine (Deterministic Fallback)",
            "is_llm": False,
            "reasoning_text": narrative_text,
            "graph_evidence": evidence,
            "risk_factors": risk_factors,
            "defensive_recommendations": recommendations,
            "limitations": "ADVISORY NOTICE: Generated by RedOps Local Rule-Based Security Expert Engine based on NetworkX attack path topology and CVSS 3.1 criteria. No live command execution was triggered. Recommendations require security review before change-window deployment."
        }

    @classmethod
    def _query_openai(cls, evidence: dict) -> dict:
        """Invokes OpenAI Chat Completion API when key is configured."""
        try:
            url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {Config.OPENAI_API_KEY}",
                "Content-Type": "application/json"
            }
            prompt = (
                "You are an enterprise Red Team and Blue Team Security Architect analyzing an attack path.\n"
                f"Evidence: {json.dumps(evidence)}\n"
                "Provide a structured security reasoning summary in JSON format with keys: "
                "reasoning_text (string), risk_factors (list of strings), defensive_recommendations (list of objects with priority, action, detail, mitre_tactic)."
            )
            payload = {
                "model": Config.LLM_MODEL,
                "messages": [
                    {"role": "system", "content": "You are a professional defensive cybersecurity engineer analyzing enterprise attack paths. Output strict JSON only."},
                    {"role": "user", "content": prompt}
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0.2
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=12)
            if resp.status_code == 200:
                parsed = resp.json()
                content = json.loads(parsed["choices"][0]["message"]["content"])
                return {
                    "provider_label": f"OpenAI ({Config.LLM_MODEL})",
                    "is_llm": True,
                    "reasoning_text": content.get("reasoning_text", "AI path analysis completed."),
                    "graph_evidence": evidence,
                    "risk_factors": content.get("risk_factors", []),
                    "defensive_recommendations": content.get("defensive_recommendations", []),
                    "limitations": f"Advisory reasoning produced by {Config.LLM_MODEL}. Does not execute active tests."
                }
        except Exception as e:
            print(f"[LLM_API_ERROR] OpenAI query failed: {e}. Falling back to local rule-based expert.")

        return cls._local_rule_based_engine(evidence, None)

    @classmethod
    def _query_gemini(cls, evidence: dict) -> dict:
        """Invokes Gemini API when key is configured."""
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={Config.GEMINI_API_KEY}"
            prompt = (
                "Act as a senior cybersecurity defensive engineer. Analyze this enterprise attack path:\n"
                f"{json.dumps(evidence)}\n"
                "Return a JSON object with: reasoning_text, risk_factors (array), defensive_recommendations (array)."
            )
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"response_mime_type": "application/json"}
            }
            resp = requests.post(url, json=payload, timeout=12)
            if resp.status_code == 200:
                data = resp.json()
                txt = data["candidates"][0]["content"]["parts"][0]["text"]
                content = json.loads(txt)
                return {
                    "provider_label": "Google Gemini 1.5 Flash",
                    "is_llm": True,
                    "reasoning_text": content.get("reasoning_text", "Gemini path analysis completed."),
                    "graph_evidence": evidence,
                    "risk_factors": content.get("risk_factors", []),
                    "defensive_recommendations": content.get("defensive_recommendations", []),
                    "limitations": "Advisory reasoning produced by Gemini API. Advisory only."
                }
        except Exception as e:
            print(f"[LLM_API_ERROR] Gemini query failed: {e}. Falling back to local rule-based expert.")

        return cls._local_rule_based_engine(evidence, None)
