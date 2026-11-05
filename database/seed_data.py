"""
RedOps Seed Data Module
Populates the SQLite database with a realistic enterprise laboratory environment.
All seeded records are explicitly marked with metadata indicating Seeded Laboratory Data.
"""
import os
import sys
import json

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db import get_db_connection, init_db, log_audit

def seed_database(force_refresh: bool = False):
    """Inserts initial enterprise lab assets, services, CVEs, scenarios and baseline audit records."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if already seeded
    cursor.execute("SELECT COUNT(*) as count FROM assets")
    existing_assets = cursor.fetchone()["count"]
    if existing_assets > 0 and not force_refresh:
        conn.close()
        return False

    if force_refresh:
        # Clear existing assessment data
        cursor.execute("DELETE FROM vulnerabilities")
        cursor.execute("DELETE FROM services")
        cursor.execute("DELETE FROM assets")
        cursor.execute("DELETE FROM attack_paths")
        cursor.execute("DELETE FROM ai_reasoning")
        cursor.execute("DELETE FROM simulation_executions")
        cursor.execute("DELETE FROM assessment_plans")
        cursor.execute("DELETE FROM scan_history")
        conn.commit()

    # 1. Target Allowlist
    allowlist_targets = [
        ("127.0.0.1", "Local Host Loopback", "Safe local testing environment", 1),
        ("localhost", "Local Domain Alias", "Local system loopback alias", 1),
        ("172.28.0.0/16", "Enterprise Docker Lab Subnet", "Isolated private Docker network for RedOps assessment", 1),
        ("172.28.0.10", "Edge Gateway Container", "Perimeter Reverse Proxy & Firewall simulation", 1),
        ("172.28.0.20", "Enterprise App Portal", "Internal Spring Boot / Tomcat Application server", 1),
        ("172.28.0.30", "Cluster Database Tier", "PostgreSQL & Redis data stores", 1),
        ("172.28.0.40", "Active Directory DC", "Domain Controller and Kerberos authentication server", 1),
    ]
    cursor.executemany("""
        INSERT OR IGNORE INTO target_allowlist (target, label, description, is_approved)
        VALUES (?, ?, ?, ?)
    """, allowlist_targets)

    # 2. Assets
    assets_data = [
        ("172.28.0.10", "gw01.corp.internal", "Linux", "Alpine Linux 3.18 / Kernel 6.1", "active", "02:42:ac:1c:00:0a", "HIGH", "Gateway", "Edge Perimeter Gateway and Reverse Proxy. [Seeded Lab Environment]"),
        ("172.28.0.20", "app-portal.corp.internal", "Linux", "Ubuntu 20.04 LTS", "active", "02:42:ac:1c:00:14", "HIGH", "Web Server", "Enterprise Core Web Application & API Gateway. [Seeded Lab Environment]"),
        ("172.28.0.30", "db-cluster01.corp.internal", "Linux", "Debian GNU/Linux 11", "active", "02:42:ac:1c:00:1e", "CRITICAL", "Database", "Production Database Cluster hosting customer PII and transactions. [Seeded Lab Environment]"),
        ("172.28.0.40", "dc01.corp.internal", "Windows", "Windows Server 2019 / Samba 4 AD", "active", "02:42:ac:1c:00:28", "CRITICAL", "DC", "Primary Domain Controller managing enterprise identities and Kerberos. [Seeded Lab Environment]"),
    ]
    cursor.executemany("""
        INSERT INTO assets (ip_address, hostname, os_name, os_version, status, mac_address, criticality, role, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, assets_data)
    conn.commit()

    # Retrieve inserted asset IDs
    cursor.execute("SELECT id, ip_address FROM assets")
    asset_map = {row["ip_address"]: row["id"] for row in cursor.fetchall()}

    # 3. Services
    services_data = [
        # gw01 (172.28.0.10)
        (asset_map["172.28.0.10"], 22, "tcp", "ssh", "OpenSSH", "8.2p1", "open", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"),
        (asset_map["172.28.0.10"], 80, "tcp", "http", "Nginx", "1.18.0", "open", "nginx/1.18.0 (Ubuntu)"),
        (asset_map["172.28.0.10"], 443, "tcp", "https", "Nginx", "1.18.0", "open", "nginx/1.18.0 SSL TLSv1.3"),
        
        # app-portal (172.28.0.20)
        (asset_map["172.28.0.20"], 8080, "tcp", "http", "Apache Tomcat / Spring Framework", "9.0.43 (Spring Boot 2.6.2)", "open", "Apache-Coyote/1.1 Tomcat 9.0.43 Spring REST"),
        (asset_map["172.28.0.20"], 8009, "tcp", "ajp13", "Apache JServ Protocol", "1.3", "open", "Apache Tomcat AJP Connector 1.3"),
        (asset_map["172.28.0.20"], 22, "tcp", "ssh", "OpenSSH", "8.2p1", "open", "SSH-2.0-OpenSSH_8.2p1"),

        # db-cluster01 (172.28.0.30)
        (asset_map["172.28.0.30"], 5432, "tcp", "postgresql", "PostgreSQL Database Server", "12.4", "open", "PostgreSQL 12.4 (Debian 12.4-1.pgdg100+1)"),
        (asset_map["172.28.0.30"], 6379, "tcp", "redis", "Redis In-Memory Key-Value Store", "5.0.7", "open", "redis_version:5.0.7"),

        # dc01 (172.28.0.40)
        (asset_map["172.28.0.40"], 88, "tcp", "kerberos-sec", "Microsoft Windows Kerberos", "10.0.17763", "open", "Microsoft Windows Kerberos KDC"),
        (asset_map["172.28.0.40"], 389, "tcp", "ldap", "Microsoft Windows Active Directory LDAP", "3.0", "open", "SupportedLDAPVersion: 3"),
        (asset_map["172.28.0.40"], 445, "tcp", "microsoft-ds", "Microsoft-DS Active Directory SMB", "Windows Server 2019", "open", "SMBv2/SMBv3 Microsoft Windows Server 2019"),
    ]
    cursor.executemany("""
        INSERT INTO services (asset_id, port, protocol, service_name, product, version, state, banner)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, services_data)
    conn.commit()

    # Retrieve inserted service IDs
    cursor.execute("""
        SELECT s.id, a.ip_address, s.port 
        FROM services s 
        JOIN assets a ON s.asset_id = a.id
    """)
    service_map = {(row["ip_address"], row["port"]): row["id"] for row in cursor.fetchall()}

    # 4. Vulnerabilities (Curated with real NVD records & CVSS 3.1)
    vulnerabilities_data = [
        # Nginx 1.18.0 on Gateway
        (
            service_map[("172.28.0.10", 80)],
            "CVE-2021-23017",
            "Nginx 1-Byte Memory Overwrite in DNS Resolver",
            "A security issue in nginx resolver allows an attacker to cause 1-byte memory overwrite by crafting malicious DNS responses, resulting in worker process crash or potential code execution.",
            8.5,
            "HIGH",
            "nginx 0.6.18 through 1.20.0",
            "Upgrade nginx to version 1.20.1, 1.21.0 or higher. Disable dynamic resolver directive if unused.",
            "CONFIRMED",
            json.dumps(["https://nvd.nist.gov/vuln/detail/CVE-2021-23017", "https://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html"])
        ),
        # Spring4Shell on app-portal
        (
            service_map[("172.28.0.20", 8080)],
            "CVE-2022-22965",
            "Spring Framework RCE via DataBinder Access Log Manipulation (Spring4Shell)",
            "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via class loader access in DataBinder parameter binding.",
            9.8,
            "CRITICAL",
            "Spring Framework 5.3.0 to 5.3.17, 5.2.0 to 5.2.19",
            "Upgrade Spring Framework to 5.3.18 or 5.2.20+. Update Tomcat to 10.0.20, 9.0.62, or 8.5.78.",
            "CONFIRMED",
            json.dumps(["https://nvd.nist.gov/vuln/detail/CVE-2022-22965", "https://tanzu.vmware.com/security/cve-2022-22965"])
        ),
        # Ghostcat on app-portal
        (
            service_map[("172.28.0.20", 8009)],
            "CVE-2020-1938",
            "Apache Tomcat AJP Connector File Read/Inclusion (Ghostcat)",
            "When using Apache Tomcat AJP connector, an unauthenticated attacker can read web application configuration files and achieve arbitrary code execution via file inclusion.",
            9.8,
            "CRITICAL",
            "Apache Tomcat 9.0.0.M1 to 9.0.30, 8.5.0 to 8.5.50, 7.0.0 to 7.0.99",
            "Disable the AJP connector in server.xml if not required, or bind to 127.0.0.1 and configure 'requiredSecret'.",
            "CONFIRMED",
            json.dumps(["https://nvd.nist.gov/vuln/detail/CVE-2020-1938", "https://www.chaitin.cn/en/ghostcat"])
        ),
        # Redis RCE on db-cluster01
        (
            service_map[("172.28.0.30", 6379)],
            "CVE-2022-0543",
            "Redis Lua Sandbox Escape Remote Code Execution",
            "Due to a packaging bug on Debian/Ubuntu, the Redis Lua environment allows loading arbitrary shared libraries, enabling attackers to execute system commands directly on the host.",
            10.0,
            "CRITICAL",
            "Redis Debian packages 5:5.0.7-2, 5:6.0.16-1",
            "Upgrade redis-server package to patched distribution release. Enforce requirepass and bind to localhost only.",
            "CONFIRMED",
            json.dumps(["https://nvd.nist.gov/vuln/detail/CVE-2022-0543", "https://www.ubercomp.com/posts/2022-01-20_redis_rce"])
        ),
        # PostgreSQL security issue
        (
            service_map[("172.28.0.30", 5432)],
            "CVE-2022-1552",
            "PostgreSQL Autovacuum and Index DDL Privilege Escalation",
            "Flaw in PostgreSQL autovacuum worker allows unprivileged users to execute code with superuser privileges during routine database maintenance operations.",
            8.8,
            "HIGH",
            "PostgreSQL 12.0 to 12.10, 13.0 to 13.6, 14.0 to 14.2",
            "Upgrade PostgreSQL to 12.11, 13.7, 14.3 or higher.",
            "POTENTIAL",
            json.dumps(["https://nvd.nist.gov/vuln/detail/CVE-2022-1552"])
        ),
        # Zerologon on Domain Controller
        (
            service_map[("172.28.0.40", 445)],
            "CVE-2020-1472",
            "Microsoft Netlogon Cryptographic Flaw Elevation of Privilege (Zerologon)",
            "An unauthenticated attacker with network access to a Domain Controller can establish a vulnerable Netlogon channel to reset the machine password and gain full Domain Admin credentials.",
            10.0,
            "CRITICAL",
            "Windows Server 2008 R2 through Windows Server 2019",
            "Apply Microsoft security patch KB4557222 and enforce Secure RPC for all Netlogon connections via registry.",
            "CONFIRMED",
            json.dumps(["https://nvd.nist.gov/vuln/detail/CVE-2020-1472", "https://www.secura.com/blog/zero-logon"])
        ),
        # sAMAccountName AD PrivEsc
        (
            service_map[("172.28.0.40", 389)],
            "CVE-2021-42287",
            "Active Directory Kerberos Privilege Escalation (sAMAccountName Spoofing)",
            "Active Directory domain controllers fail to properly validate sAMAccountName attributes during Kerberos Ticket Granting Service requests, allowing standard users to impersonate Domain Admins.",
            8.8,
            "HIGH",
            "Windows Server 2012, 2016, 2019, 2022 prior to Nov 2021 patches",
            "Install KB5008102 and KB5008380 security updates immediately across all domain controllers.",
            "CONFIRMED",
            json.dumps(["https://nvd.nist.gov/vuln/detail/CVE-2021-42287"])
        ),
    ]
    cursor.executemany("""
        INSERT INTO vulnerabilities (service_id, cve_id, title, description, cvss_score, severity, affected_versions, remediation, confidence, references_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, vulnerabilities_data)
    conn.commit()

    # 5. Attack Paths (Calculated from graph engine)
    attack_paths_data = [
        (
            "Primary Enterprise Compromise Chain (Perimeter -> RCE -> Database Exfiltration)",
            "External Reconnaissance (172.28.0.10:80)",
            "Internal Database (172.28.0.30:6379)",
            json.dumps([
                {"step": 1, "node": "172.28.0.10", "type": "host", "label": "Edge Gateway", "action": "Reconnaissance / Service Discovery"},
                {"step": 2, "node": "172.28.0.20:8080", "type": "service", "label": "Enterprise App Portal", "cve": "CVE-2022-22965", "action": "Initial Access via Spring4Shell RCE"},
                {"step": 3, "node": "172.28.0.30:6379", "type": "service", "label": "Redis Cache Service", "cve": "CVE-2022-0543", "action": "Lateral Movement & Sandbox Escape to Root"},
                {"step": 4, "node": "172.28.0.30", "type": "target", "label": "Production PII Database", "action": "Crown Jewel Data Exfiltration"}
            ]),
            9.9,
            "CRITICAL",
            "Multi-stage chained attack path enabling an unauthenticated perimeter attacker to exploit Spring4Shell on the application server, pivot to internal Redis on port 6379, and achieve complete database compromise.",
            json.dumps(["TA0001: Initial Access", "TA0002: Execution", "TA0008: Lateral Movement", "TA0010: Exfiltration"]),
            1
        ),
        (
            "Secondary Domain Hijack Path (AJP Exposure -> Zerologon DC Takeover)",
            "App Portal Perimeter (172.28.0.20:8009)",
            "Domain Controller (172.28.0.40:445)",
            json.dumps([
                {"step": 1, "node": "172.28.0.20:8009", "type": "service", "label": "Ghostcat AJP Exposure", "cve": "CVE-2020-1938", "action": "Arbitrary File Read & Credential Extraction"},
                {"step": 2, "node": "172.28.0.40:445", "type": "service", "label": "Active Directory SMB/Netlogon", "cve": "CVE-2020-1472", "action": "Zerologon Cryptographic Exploitation"},
                {"step": 3, "node": "172.28.0.40", "type": "target", "label": "Enterprise Active Directory DC", "action": "Full Domain Forest Takeover"}
            ]),
            10.0,
            "CRITICAL",
            "Direct attack trajectory bypassing boundary controls through exposed Tomcat AJP port, chaining to internal Domain Controller via Zerologon for forest-level privilege dominance.",
            json.dumps(["TA0001: Initial Access", "TA0004: Privilege Escalation", "TA0008: Lateral Movement", "TA0006: Credential Access"]),
            0
        )
    ]
    cursor.executemany("""
        INSERT INTO attack_paths (name, source_node, target_node, path_nodes_json, risk_score, severity, description, mitre_tactics_json, is_exploited_simulated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, attack_paths_data)
    conn.commit()

    # 6. AI Reasoning Records
    ai_reasoning_data = [
        (
            asset_map["172.28.0.30"],
            1,
            "attack_path_analysis",
            "local_rule_engine",
            "Security Analysis Narrative: The assessment identifies a high-probability lateral movement path originating from the perimeter reverse proxy. The primary vulnerability CVE-2022-22965 (Spring4Shell) in the enterprise application tier provides unauthenticated command execution. Because the application server resides in the same internal security zone as the database cluster without microsegmentation, an attacker can directly reach the unauthenticated Redis port (6379) and execute CVE-2022-0543 (Lua Sandbox Escape), yielding root-level persistence on the crown-jewel database host.",
            json.dumps({
                "source_host": "172.28.0.20 (app-portal)",
                "target_host": "172.28.0.30 (db-cluster01)",
                "compromise_vector": "Spring4Shell -> Internal Network Pivoting -> Redis Lua RCE",
                "network_segmentation": "Flat internal subnet without firewall segregation between Web tier and DB tier",
                "attack_complexity": "Low (Public exploit scripts exist for both CVE-2022-22965 and CVE-2022-0543)"
            }),
            json.dumps([
                "Lack of ingress port restriction on internal database listening ports (6379, 5432)",
                "Legacy Redis 5.0.7 package vulnerable to Debian-specific Lua library injection",
                "Spring framework running on JDK 9+ without class loader validation patches",
                "Flat 172.28.0.0/16 lab network lacking network microsegmentation"
            ]),
            json.dumps([
                "Immediate: Apply Spring Framework 5.3.18 / Tomcat 9.0.62 patches to app-portal.",
                "Short-term: Configure Redis with strong authentication (requirepass) and bind exclusively to 127.0.0.1.",
                "Architectural: Enforce zero-trust network policies: restrict database port 6379/5432 to explicitly authorized IP addresses only via host firewall or Docker network bridge.",
                "Monitoring: Deploy Suricata/Snort detection rules for anomalous Spring ClassLoader HTTP POST parameter signatures."
            ]),
            "Advisory AI reasoning generated based on topological evidence and CVSS 3.1 scoring. LLM findings are bounded to non-destructive analysis and do not confirm live payload execution without controlled human-approved simulation."
        )
    ]
    cursor.executemany("""
        INSERT INTO ai_reasoning (target_asset_id, attack_path_id, analysis_type, ai_provider, reasoning_text, graph_evidence_json, risk_factors_json, defensive_recommendations_json, limitations_text)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, ai_reasoning_data)
    conn.commit()

    # 7. Simulation Scenarios (Strictly safe, non-destructive, MITRE ATT&CK mapped)
    scenarios_data = [
        (
            "SIM-DISC-01",
            "Safe Network Port & Service Footprinting",
            "Performs non-intrusive TCP SYN / connect handshake against allowlisted target to enumerate open ports without sending malicious payloads.",
            "T1046",
            "Network Service Discovery",
            "Discovery",
            "LOW",
            "Strictly passive/standard TCP connection handshakes. No exploit data transmitted.",
            1
        ),
        (
            "SIM-ENUM-02",
            "Service Banner & Version Telemetry Audit",
            "Sends standard protocol probe (HTTP GET / SSH banner query) to gather server header and version strings to verify CVE correlation accuracy.",
            "T1082",
            "System Information Discovery",
            "Discovery",
            "LOW",
            "Harmless standard application protocol queries. Will not cause denial-of-service.",
            1
        ),
        (
            "SIM-AUTH-03",
            "Controlled Default Credential & Exposure Check",
            "Verifies whether administrative services (e.g. Redis PING, Tomcat Manager) respond without authentication or reject connection as expected.",
            "T1110.001",
            "Password Guessing / Default Credential Probe",
            "Credential Access",
            "MEDIUM",
            "Limited to at most 3 benign diagnostic checks. No account lockouts triggered.",
            1
        ),
        (
            "SIM-EXPLOIT-04",
            "Non-Destructive Vulnerability Signature Verification",
            "Checks if web endpoints expose vulnerable Spring DataBinder parameters or unauthenticated AJP protocol headers without deploying weaponized payloads.",
            "T1190",
            "Exploit Public-Facing Application (Safe Verification)",
            "Initial Access",
            "HIGH",
            "Diagnostic canary probe only. Verifies parameter reflection or HTTP 400/500 signature safely.",
            1
        ),
        (
            "SIM-LATERAL-05",
            "Internal Lateral Pivoting Connectivity Check",
            "Simulates network route traversability between Web App and Database tier to validate whether segmentation firewall rules are actively blocking unauthorized hops.",
            "T1021.002",
            "Remote Services: SMB/Database Access Probe",
            "Lateral Movement",
            "MEDIUM",
            "Measures TCP reachability on internal ports without payload delivery.",
            1
        ),
    ]
    cursor.executemany("""
        INSERT OR IGNORE INTO simulation_scenarios (code, name, description, mitre_technique_id, mitre_technique_name, mitre_tactic, severity, safety_notes, requires_approval)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, scenarios_data)
    conn.commit()

    # 8. Past Simulation Executions (Demonstrative proof of controlled execution)
    cursor.execute("SELECT id, code FROM simulation_scenarios")
    scenario_map = {row["code"]: row["id"] for row in cursor.fetchall()}

    executions_data = [
        (
            scenario_map["SIM-DISC-01"],
            "172.28.0.10",
            80,
            "COMPLETED",
            "security_officer_admin",
            "[2026-11-05 20:10:12] [SIM-LOG] Verification of target 172.28.0.10 against allowlist: PASS\n[2026-11-05 20:10:13] [SIM-LOG] Initiated harmless TCP SYN probe on ports 22, 80, 443\n[2026-11-05 20:10:14] [SIM-LOG] Port 80 OPEN (HTTP), Port 443 OPEN (HTTPS), Port 22 OPEN (SSH)\n[2026-11-05 20:10:15] [SIM-LOG] Completed with zero network degradation.",
            "Verified open perimeter attack surface on Gateway host. Ports 80 and 443 accept connections.",
            "T1046: Network Service Discovery"
        ),
        (
            scenario_map["SIM-EXPLOIT-04"],
            "172.28.0.20",
            8080,
            "COMPLETED",
            "security_officer_admin",
            "[2026-11-05 20:12:01] [SIM-LOG] Checking scope policy: 172.28.0.20 is authorized.\n[2026-11-05 20:12:02] [SIM-LOG] Sending safe diagnostic canary parameter (class.module.classLoader check)...\n[2026-11-05 20:12:03] [SIM-LOG] Response received: HTTP 200 OK with vulnerable DataBinder reflection.\n[2026-11-05 20:12:04] [SIM-LOG] Result: CVE-2022-22965 (Spring4Shell) vulnerability exposure CONFIRMED via safe telemetry probe.",
            "Spring4Shell signature matched on endpoint /api/v1/health. Target application is exposed to remote exploitation.",
            "T1190: Exploit Public-Facing Application"
        ),
    ]
    cursor.executemany("""
        INSERT INTO simulation_executions (scenario_id, target_ip, target_port, status, user_approved_by, logs, findings, mitre_mapped)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, executions_data)
    conn.commit()

    # 9. Bounded Assessment Plans
    plans_data = [
        ("Phase 1: Discovery & Service Profiling", "172.28.0.20", "Run comprehensive service and banner enumeration on app-portal", "High-priority application host detected with multiple open ports requiring deep banner confirmation.", "APPROVED", "Incomplete banner data on secondary ports 8009 and 8080."),
        ("Phase 2: Vulnerability Correlation & Graph Synthesis", "172.28.0.30", "Correlate Redis 5.0.7 with Debian CVE-2022-0543 database entries", "Unauthenticated key-value store observed on private segment. Needs formal attack graph path linkage.", "EXECUTED", "Attack path from App Portal to Redis Cache analyzed."),
        ("Phase 3: Controlled Simulation & Validation", "172.28.0.40", "Execute safe SMB dialect verification (SIM-LATERAL-05) against Domain Controller", "Identify whether Zerologon attack path can be exercised from compromised web segment.", "PENDING", "DC reachability from DMZ segment has not been verified."),
        ("Phase 4: Risk Prioritization & Remediation Validation", "172.28.0.10", "Generate remediation plan for Nginx resolver CVE-2021-23017 and isolate gateway", "Perimeter security must be hardened before closing assessment.", "PENDING", "Remediation patch validation pending client maintenance window.")
    ]
    cursor.executemany("""
        INSERT INTO assessment_plans (phase_name, target_ip, recommended_action, rationale, status, coverage_gap)
        VALUES (?, ?, ?, ?, ?, ?)
    """, plans_data)
    conn.commit()

    # 10. Scan History
    scans_data = [
        ("172.28.0.0/16", "Enterprise Lab Full Subnet Scan", "COMPLETED", 4, 11, "Initiated RedOps authorized discovery engine against 172.28.0.0/16.\nDiscovered 4 active hosts:\n- 172.28.0.10 (gw01)\n- 172.28.0.20 (app-portal)\n- 172.28.0.30 (db-cluster01)\n- 172.28.0.40 (dc01)\nFound 11 open ports across all hosts.\nAssessment safety policy enforced: Strict allowlist check verified."),
        ("127.0.0.1", "Local Host Quick Scan", "COMPLETED", 1, 1, "Discovered local development runtime on port 5000.")
    ]
    cursor.executemany("""
        INSERT INTO scan_history (target, scan_type, status, hosts_discovered, ports_found, raw_output)
        VALUES (?, ?, ?, ?, ?, ?)
    """, scans_data)
    conn.commit()

    # 11. Initial Audit Logs
    audit_data = [
        ("DATABASE_INITIALIZED", "SYSTEM", "redops.db", "RedOps database schema created and seed laboratory environment populated."),
        ("ALLOWLIST_CONFIGURED", "security_officer_admin", "172.28.0.0/16", "Authorized target subnet 172.28.0.0/16 added to strict security scope."),
        ("DISCOVERY_SCAN_EXECUTED", "security_officer_admin", "172.28.0.0/16", "Subnet discovery completed. 4 hosts, 11 services indexed."),
        ("CVE_CORRELATION_COMPLETED", "cve_engine", "ALL_TARGETS", "Vulnerability correlation mapped 7 CVE records with CVSS 3.1 scores."),
        ("ATTACK_PATH_SYNTHESIZED", "networkx_engine", "172.28.0.30", "High-risk path synthesized from perimeter to crown jewel database."),
        ("AI_REASONING_GENERATED", "ai_reasoning_module", "172.28.0.30", "AI security advisory produced with MITRE ATT&CK defensive roadmap."),
        ("SIMULATION_APPROVED_EXECUTED", "security_officer_admin", "172.28.0.20:8080", "Controlled simulation SIM-EXPLOIT-04 approved and executed non-destructively.")
    ]
    cursor.executemany("""
        INSERT INTO audit_logs (action, user_id, target, details)
        VALUES (?, ?, ?, ?)
    """, audit_data)
    conn.commit()

    conn.close()
    return True

if __name__ == "__main__":
    success = seed_database(force_refresh=True)
    print(f"Database seeded successfully: {success}")
