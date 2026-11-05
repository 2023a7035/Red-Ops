"""
RedOps Reporting Engine
Generates executive-level cybersecurity assessment reports in PDF and CSV formats.
Includes threat posture summaries, asset inventories, CVE correlations, attack path diagrams,
AI reasoning narratives, simulation observations, and prioritized remediation matrices.
"""
import os
import csv
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from config import Config
from database.db import get_db_connection, log_audit
from models.vulnerability import VulnerabilityModel

class ReportingService:
    @classmethod
    def generate_pdf_report(cls) -> str:
        """
        Builds a comprehensive, professional cybersecurity assessment PDF report using ReportLab.
        Returns the absolute file path of the generated PDF.
        """
        os.makedirs(Config.REPORTS_DIR, exist_ok=True)
        filename = f"RedOps_Security_Assessment_Report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        file_path = os.path.join(Config.REPORTS_DIR, filename)

        doc = SimpleDocTemplate(
            file_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom Cyber Command Center Styling Palette
        c_primary = colors.HexColor("#090d16")     # Dark Navy
        c_accent = colors.HexColor("#0077fe")      # Cyber Blue
        c_cyan = colors.HexColor("#00b4d8")        # Electric Cyan
        c_critical = colors.HexColor("#ff2a5f")    # Crimson Red
        c_high = colors.HexColor("#ff7700")        # Warning Orange
        c_text = colors.HexColor("#1e293b")        # Deep Slate

        # Typography Styles
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=c_accent,
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            'DocSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=15
        )
        h1_style = ParagraphStyle(
            'SectionH1',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=c_primary,
            spaceBefore=14,
            spaceAfter=8
        )
        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=14,
            textColor=c_accent,
            spaceBefore=8,
            spaceAfter=4
        )
        body_style = ParagraphStyle(
            'BodyText',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=c_text
        )
        table_hdr_style = ParagraphStyle(
            'TableHdr',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=10,
            textColor=colors.white
        )
        table_body_style = ParagraphStyle(
            'TableBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=10,
            textColor=c_text
        )

        elements = []

        # 1. Header Banner
        elements.append(Paragraph("REDOPS SECURITY ASSESSMENT REPORT", title_style))
        elements.append(Paragraph(
            "<b>Automated Enterprise Red Team Assessment & Attack Simulation Platform</b><br/>"
            f"Assessment Date: {datetime.utcnow().strftime('%B %d, %Y - %H:%M:%S UTC')} | Classification: <b>CONFIDENTIAL / AUTHORIZED SECURITY ASSESSMENT</b>",
            subtitle_style
        ))
        elements.append(HRFlowable(width="100%", thickness=2, color=c_accent, spaceBefore=0, spaceAfter=15))

        # 2. Executive Summary
        elements.append(Paragraph("1. Executive Summary & Assessment Scope", h1_style))
        summary_text = (
            "This document presents the technical findings, topological graph analysis, and simulated attack chains "
            "evaluated by the RedOps platform. Testing was conducted exclusively within authorized laboratory scopes "
            "and strictly enforce allowlist policies. The assessment evaluated network boundaries, exposed daemon services, "
            "correlated CVE records, and synthesized multi-hop lateral movement attack paths toward enterprise crown jewel assets."
        )
        elements.append(Paragraph(summary_text, body_style))
        elements.append(Spacer(1, 10))

        # Fetch Data
        conn = get_db_connection()
        assets = conn.execute("SELECT * FROM assets ORDER BY id").fetchall()
        services = conn.execute("SELECT * FROM services").fetchall()
        vulns = VulnerabilityModel.get_all()
        paths = conn.execute("SELECT * FROM attack_paths ORDER BY risk_score DESC").fetchall()
        ai_records = conn.execute("SELECT * FROM ai_reasoning ORDER BY id DESC LIMIT 1").fetchall()
        sim_executions = conn.execute("""
            SELECT e.*, s.name as scenario_name, s.code as scenario_code
            FROM simulation_executions e
            JOIN simulation_scenarios s ON e.scenario_id = s.id
            ORDER BY e.executed_at DESC LIMIT 5
        """).fetchall()
        allowlist = conn.execute("SELECT * FROM target_allowlist").fetchall()
        conn.close()

        # Scope Table
        scope_rows = [[Paragraph("<b>Authorized Scope / Allowlist</b>", table_hdr_style), Paragraph("<b>Description</b>", table_hdr_style), Paragraph("<b>Status</b>", table_hdr_style)]]
        for a in allowlist:
            scope_rows.append([
                Paragraph(a["target"], table_body_style),
                Paragraph(a.get("description", "Lab Environment"), table_body_style),
                Paragraph("APPROVED", table_body_style)
            ])
        t_scope = Table(scope_rows, colWidths=[140, 280, 80])
        t_scope.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), c_primary),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_scope)
        elements.append(Spacer(1, 14))

        # 3. Discovered Asset & Service Inventory
        elements.append(Paragraph("2. Discovered Assets & Attack Surface", h1_style))
        asset_rows = [[
            Paragraph("<b>Host / IP</b>", table_hdr_style),
            Paragraph("<b>Hostname</b>", table_hdr_style),
            Paragraph("<b>OS / Role</b>", table_hdr_style),
            Paragraph("<b>Criticality</b>", table_hdr_style),
            Paragraph("<b>Open Ports</b>", table_hdr_style)
        ]]
        for a in assets:
            host_svcs = [str(s["port"]) for s in services if s["asset_id"] == a["id"]]
            asset_rows.append([
                Paragraph(a["ip_address"], table_body_style),
                Paragraph(a["hostname"] or "Unknown", table_body_style),
                Paragraph(f"{a['role']} ({a['os_name']})", table_body_style),
                Paragraph(f"<b>{a['criticality']}</b>", table_body_style),
                Paragraph(", ".join(host_svcs) or "None", table_body_style)
            ])
        t_assets = Table(asset_rows, colWidths=[90, 130, 130, 70, 80])
        t_assets.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), c_accent),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_assets)
        elements.append(Spacer(1, 14))

        # 4. Vulnerability Correlation Findings
        elements.append(Paragraph("3. Correlated Vulnerabilities (NVD / CVE)", h1_style))
        vuln_rows = [[
            Paragraph("<b>CVE ID</b>", table_hdr_style),
            Paragraph("<b>Target Host:Port</b>", table_hdr_style),
            Paragraph("<b>CVSS / Severity</b>", table_hdr_style),
            Paragraph("<b>Vulnerability Title & Remediation</b>", table_hdr_style)
        ]]
        for v in vulns[:8]:
            sev_color = "#ff2a5f" if v["severity"] == "CRITICAL" else "#ff7700" if v["severity"] == "HIGH" else "#0077fe"
            vuln_rows.append([
                Paragraph(f"<b>{v['cve_id']}</b>", table_body_style),
                Paragraph(f"{v['ip_address']}:{v['port']}", table_body_style),
                Paragraph(f"<font color='{sev_color}'><b>{v['cvss_score']} {v['severity']}</b></font>", table_body_style),
                Paragraph(f"<b>{v['title']}</b><br/><font color='#475569'>Remediation: {v['remediation']}</font>", table_body_style)
            ])
        t_vulns = Table(vuln_rows, colWidths=[95, 95, 80, 230])
        t_vulns.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), c_primary),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_vulns)
        elements.append(Spacer(1, 14))

        # 5. Graph-Based Attack Path Analysis
        elements.append(Paragraph("4. Graph-Based Attack-Path Analysis (NetworkX)", h1_style))
        path_desc = (
            "The RedOps graph engine modeled topological asset connectivity and CVE exploitability. "
            "Chained paths identify multi-step escalation routes from perimeter vectors to crown jewels."
        )
        elements.append(Paragraph(path_desc, body_style))
        elements.append(Spacer(1, 6))

        for p in paths[:2]:
            elements.append(Paragraph(f"<b>• {p['name']}</b> (Risk Score: <b>{p['risk_score']}/10.0 [{p['severity']}]</b>)", h2_style))
            elements.append(Paragraph(f"Trajectory: <i>{p['source_node']} &rarr; {p['target_node']}</i>", body_style))
            elements.append(Paragraph(f"Description: {p['description']}", body_style))
            elements.append(Spacer(1, 6))

        # 6. AI Reasoning & Threat Narrative
        if ai_records:
            ai_data = ai_records[0]
            elements.append(Paragraph("5. AI Reasoning & Threat Narrative (LLM Module)", h1_style))
            elements.append(Paragraph(f"Engine: <b>{ai_data['ai_provider']}</b>", h2_style))
            elements.append(Paragraph(ai_data["reasoning_text"].replace("\n", "<br/>"), body_style))
            elements.append(Spacer(1, 6))
            elements.append(Paragraph(f"<i>Limitations & Advisory Notice: {ai_data['limitations_text']}</i>", subtitle_style))
            elements.append(Spacer(1, 10))

        # 7. Controlled Simulation Findings
        elements.append(Paragraph("6. Controlled Simulation Observations", h1_style))
        sim_rows = [[
            Paragraph("<b>Scenario Code & Name</b>", table_hdr_style),
            Paragraph("<b>Target</b>", table_hdr_style),
            Paragraph("<b>Approved By</b>", table_hdr_style),
            Paragraph("<b>Status & Observations</b>", table_hdr_style)
        ]]
        for s in sim_executions:
            sim_rows.append([
                Paragraph(f"<b>{s['scenario_code']}</b><br/>{s['scenario_name']}", table_body_style),
                Paragraph(f"{s['target_ip']}:{s['target_port']}", table_body_style),
                Paragraph(s["user_approved_by"], table_body_style),
                Paragraph(f"<b>[{s['status']}]</b> {s['findings'] or 'Executed harmless telemetry probe.'}", table_body_style)
            ])
        t_sim = Table(sim_rows, colWidths=[120, 80, 80, 220])
        t_sim.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), c_accent),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_sim)
        elements.append(Spacer(1, 14))

        # 8. Prioritized Remediation Roadmap
        elements.append(Paragraph("7. Prioritized Remediation Roadmap", h1_style))
        remediation_rows = [
            [Paragraph("<b>Priority Level</b>", table_hdr_style), Paragraph("<b>Target Focus</b>", table_hdr_style), Paragraph("<b>Defensive Action Plan</b>", table_hdr_style)],
            [Paragraph("<font color='#ff2a5f'><b>P0 - IMMEDIATE</b></font>", table_body_style), Paragraph("app-portal (172.28.0.20)", table_body_style), Paragraph("Apply vendor patches for Spring4Shell (CVE-2022-22965) and disable Tomcat AJP 8009 (Ghostcat).", table_body_style)],
            [Paragraph("<font color='#ff7700'><b>P1 - HIGH</b></font>", table_body_style), Paragraph("db-cluster01 (172.28.0.30)", table_body_style), Paragraph("Upgrade Redis package, enforce 'requirepass' authentication, bind 6379 to 127.0.0.1.", table_body_style)],
            [Paragraph("<font color='#0077fe'><b>P2 - MEDIUM</b></font>", table_body_style), Paragraph("dc01 (172.28.0.40)", table_body_style), Paragraph("Deploy KB4557222 to block Zerologon Netlogon spoofing.", table_body_style)],
            [Paragraph("<b>P3 - ARCHITECTURAL</b>", table_body_style), Paragraph("All Lab Segments", table_body_style), Paragraph("Implement network microsegmentation between DMZ and database clusters.", table_body_style)]
        ]
        t_rem = Table(remediation_rows, colWidths=[95, 125, 280])
        t_rem.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), c_primary),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_rem)

        # Build PDF
        doc.build(elements)
        log_audit("REPORT_PDF_GENERATED", details=f"Generated executive PDF report: {filename}")
        return file_path

    @classmethod
    def generate_csv_vulnerabilities(cls) -> str:
        """Exports vulnerability findings to a clean CSV file."""
        os.makedirs(Config.REPORTS_DIR, exist_ok=True)
        filename = f"RedOps_Vulnerabilities_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        file_path = os.path.join(Config.REPORTS_DIR, filename)

        vulns = VulnerabilityModel.get_all()

        with open(file_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["CVE ID", "Title", "Severity", "CVSS Score", "Target IP", "Hostname", "Port", "Service", "Product", "Version", "Remediation", "Confidence"])
            for v in vulns:
                writer.writerow([
                    v["cve_id"],
                    v["title"],
                    v["severity"],
                    v["cvss_score"],
                    v["ip_address"],
                    v["hostname"],
                    v["port"],
                    v["service_name"],
                    v["product"],
                    v["version"],
                    v["remediation"],
                    v["confidence"]
                ])

        log_audit("REPORT_CSV_GENERATED", details=f"Generated vulnerabilities CSV: {filename}")
        return file_path

    @classmethod
    def generate_csv_assets(cls) -> str:
        """Exports discovered asset inventory to a CSV file."""
        os.makedirs(Config.REPORTS_DIR, exist_ok=True)
        filename = f"RedOps_Assets_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        file_path = os.path.join(Config.REPORTS_DIR, filename)

        conn = get_db_connection()
        assets = conn.execute("""
            SELECT a.ip_address, a.hostname, a.os_name, a.os_version, a.criticality, a.role,
                   s.port, s.protocol, s.service_name, s.product, s.version, s.banner
            FROM assets a
            LEFT JOIN services s ON a.id = s.asset_id
            ORDER BY a.ip_address, s.port
        """).fetchall()
        conn.close()

        with open(file_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "Hostname", "OS Name", "OS Version", "Criticality", "Role", "Port", "Protocol", "Service", "Product", "Version", "Banner"])
            for a in assets:
                writer.writerow([
                    a["ip_address"],
                    a["hostname"],
                    a["os_name"],
                    a["os_version"],
                    a["criticality"],
                    a["role"],
                    a["port"],
                    a["protocol"],
                    a["service_name"],
                    a["product"],
                    a["version"],
                    a["banner"]
                ])

        log_audit("REPORT_CSV_GENERATED", details=f"Generated assets CSV: {filename}")
        return file_path
