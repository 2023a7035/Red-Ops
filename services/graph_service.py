"""
RedOps Graph Engine
Constructs directed cybersecurity threat graphs using NetworkX.
Calculates chained attack paths, centrality metrics, exploit risk vectors, and Cytoscape.js payloads.
Clearly distinguishes potential theoretical paths from confirmed simulations.
"""
import networkx as nx
import json
from database.db import get_db_connection, log_audit
from models.attack_path import AttackPathModel

class GraphService:
    @classmethod
    def build_networkx_graph(cls):
        """
        Constructs a complete NetworkX directed graph (DiGraph) from SQLite assets, services, and CVEs.
        Nodes represent: Entrypoints, Hosts, Services, Vulnerabilities, and Crown Jewel Targets.
        Edges represent: REACHABLE_FROM, EXPOSES, HAS_CVE, LATERAL_MOVEMENT, COMPROMISES.
        """
        G = nx.DiGraph()
        conn = get_db_connection()

        # 1. Fetch Assets
        assets = conn.execute("SELECT * FROM assets").fetchall()
        # 2. Fetch Services
        services = conn.execute("SELECT * FROM services").fetchall()
        # 3. Fetch Vulnerabilities
        vulns = conn.execute("""
            SELECT v.*, s.asset_id, s.port, a.ip_address
            FROM vulnerabilities v
            JOIN services s ON v.service_id = s.id
            JOIN assets a ON s.asset_id = a.id
        """).fetchall()
        conn.close()

        # Add External Attacker Entrypoint Node
        G.add_node("entry_external", 
                   id="entry_external",
                   label="External Threat Actor",
                   type="entrypoint",
                   category="Threat Vector",
                   criticality="CRITICAL",
                   risk_weight=1.0)

        # Add Host Nodes
        for a in assets:
            node_id = f"host_{a['id']}"
            is_crown_jewel = a["criticality"] in ("CRITICAL", "HIGH") and a["role"] in ("Database", "DC")
            G.add_node(
                node_id,
                id=node_id,
                label=f"{a['hostname']}\n({a['ip_address']})",
                ip=a["ip_address"],
                hostname=a["hostname"],
                type="target" if is_crown_jewel else "host",
                role=a["role"],
                os=f"{a['os_name']} {a['os_version']}",
                criticality=a["criticality"],
                is_crown_jewel=is_crown_jewel,
                risk_weight=1.5 if is_crown_jewel else 1.0
            )

        # Add Service Nodes and Connect to Hosts
        for s in services:
            svc_node_id = f"svc_{s['id']}"
            host_node_id = f"host_{s['asset_id']}"
            G.add_node(
                svc_node_id,
                id=svc_node_id,
                label=f"{s['service_name'].upper()}:{s['port']}\n({s['product'] or ''})",
                port=s["port"],
                protocol=s["protocol"],
                service_name=s["service_name"],
                product=s["product"],
                version=s["version"],
                type="service",
                risk_weight=0.8
            )
            # Host exposes service
            G.add_edge(host_node_id, svc_node_id, relation="EXPOSES", weight=1.0)

        # Add Vulnerability Nodes and Connect to Services
        for v in vulns:
            vuln_node_id = f"cve_{v['id']}"
            svc_node_id = f"svc_{v['service_id']}"
            host_node_id = f"host_{v['asset_id']}"

            G.add_node(
                vuln_node_id,
                id=vuln_node_id,
                label=f"{v['cve_id']}\nCVSS {v['cvss_score']} [{v['severity']}]",
                cve_id=v["cve_id"],
                title=v["title"],
                cvss_score=v["cvss_score"],
                severity=v["severity"],
                remediation=v["remediation"],
                confidence=v["confidence"],
                type="vulnerability",
                risk_weight=v["cvss_score"] / 10.0
            )
            # Service has vulnerability
            G.add_edge(svc_node_id, vuln_node_id, relation="HAS_VULNERABILITY", weight=0.5)

            # High or Critical CVEs allow exploitation to host or lateral compromise
            if v["severity"] in ("CRITICAL", "HIGH"):
                G.add_edge(vuln_node_id, host_node_id, relation="ENABLES_HOST_COMPROMISE", weight=0.2)

        # Connect External Attacker to Perimeter Services
        # Typically Gateway / Web ports 80, 443, 8080
        for s in services:
            if s["port"] in (80, 443, 8080, 8009):
                svc_node_id = f"svc_{s['id']}"
                G.add_edge("entry_external", svc_node_id, relation="PERIMETER_PROBE", weight=1.0)

        # Synthesize Lateral Movement Edges across Subnet / Trust Boundaries
        # e.g., Compromised Web App (172.28.0.20) -> Database (172.28.0.30) & DC (172.28.0.40)
        app_host = None
        db_host = None
        dc_host = None
        gw_host = None

        for a in assets:
            if "172.28.0.10" in a["ip_address"]:
                gw_host = f"host_{a['id']}"
            elif "172.28.0.20" in a["ip_address"]:
                app_host = f"host_{a['id']}"
            elif "172.28.0.30" in a["ip_address"]:
                db_host = f"host_{a['id']}"
            elif "172.28.0.40" in a["ip_address"]:
                dc_host = f"host_{a['id']}"

        if gw_host and app_host:
            G.add_edge(gw_host, app_host, relation="REVERSE_PROXY_FORWARD", weight=0.8)

        if app_host and db_host:
            G.add_edge(app_host, db_host, relation="LATERAL_INTERNAL_PIVOT", weight=0.6)

        if app_host and dc_host:
            G.add_edge(app_host, dc_host, relation="LATERAL_INTERNAL_PIVOT", weight=0.6)

        return G

    @classmethod
    def analyze_attack_paths(cls):
        """
        Uses NetworkX shortest path and simple path algorithms to find attack chains
        from Entrypoint to Crown Jewel Target Nodes.
        """
        G = cls.build_networkx_graph()
        target_nodes = [n for n, d in G.nodes(data=True) if d.get("is_crown_jewel") or d.get("type") == "target"]
        source_node = "entry_external"

        synthesized_paths = []

        for tgt in target_nodes:
            if nx.has_path(G, source_node, tgt):
                # Find all simple paths (bounded to length 8 to avoid cyclic explosions)
                paths = list(nx.all_simple_paths(G, source=source_node, target=tgt, cutoff=7))
                for path in paths[:3]:  # Top paths per target
                    # Calculate cumulative risk score
                    cvss_total = 0.0
                    cve_count = 0
                    steps = []

                    for idx, node_id in enumerate(path):
                        node_data = G.nodes[node_id]
                        if node_data.get("type") == "vulnerability":
                            cvss_total += node_data.get("cvss_score", 0.0)
                            cve_count += 1
                        steps.append({
                            "step": idx + 1,
                            "node_id": node_id,
                            "label": node_data.get("label", node_id).replace("\n", " "),
                            "type": node_data.get("type", "unknown")
                        })

                    base_risk = (cvss_total / max(cve_count, 1)) if cve_count > 0 else 7.0
                    risk_score = min(10.0, round(base_risk * 1.05, 1))
                    severity = "CRITICAL" if risk_score >= 9.0 else "HIGH" if risk_score >= 7.0 else "MEDIUM"

                    target_name = G.nodes[tgt].get("label", tgt).split("\n")[0]
                    synthesized_paths.append({
                        "name": f"Potential Breach Path to {target_name}",
                        "source_node": "External Threat Actor",
                        "target_node": target_name,
                        "path_nodes": steps,
                        "risk_score": risk_score,
                        "severity": severity,
                        "cve_count": cve_count,
                        "description": f"Potential multi-hop attack trajectory traversing {len(steps)} graph nodes from external perimeter to {target_name}.",
                        "mitre_tactics": ["TA0001: Initial Access", "TA0002: Execution", "TA0008: Lateral Movement", "TA0010: Exfiltration"]
                    })

        return synthesized_paths

    @classmethod
    def get_cytoscape_elements(cls):
        """
        Converts the NetworkX threat graph into JSON elements formatted specifically for Cytoscape.js.
        Embeds node classes, colors, glyphs, and edge relationships.
        """
        G = cls.build_networkx_graph()
        elements = []

        # Convert Nodes
        for node_id, data in G.nodes(data=True):
            node_type = data.get("type", "host")
            elements.append({
                "group": "nodes",
                "data": {
                    "id": node_id,
                    "label": data.get("label", node_id),
                    "type": node_type,
                    "ip": data.get("ip", ""),
                    "hostname": data.get("hostname", ""),
                    "criticality": data.get("criticality", "MEDIUM"),
                    "role": data.get("role", ""),
                    "port": data.get("port", ""),
                    "cve_id": data.get("cve_id", ""),
                    "cvss_score": data.get("cvss_score", ""),
                    "severity": data.get("severity", ""),
                    "remediation": data.get("remediation", ""),
                    "description": data.get("title", "")
                },
                "classes": f"type-{node_type} severity-{data.get('severity', 'none').lower()} criticality-{data.get('criticality', 'none').lower()}"
            })

        # Convert Edges
        edge_id = 0
        for u, v, data in G.edges(data=True):
            edge_id += 1
            relation = data.get("relation", "CONNECTED_TO")
            elements.append({
                "group": "edges",
                "data": {
                    "id": f"e{edge_id}",
                    "source": u,
                    "target": v,
                    "label": relation,
                    "weight": data.get("weight", 1.0)
                },
                "classes": f"rel-{relation.lower()}"
            })

        return elements
