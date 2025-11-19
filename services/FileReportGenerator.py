# Generate reports based on system results
# The systems generates PDF and Excel
# STRUCTURE
# NUMBER OF VULNERABILITIES DETECTED || Should be filtered with medium risk
# AI SUMMARY OF RESULTS
# AI RECOMMENDATIONS BASED ON RESULTS
# SCAN DETAILS || i.e., DOMAIN , IP ADDRESS , SERVER OS (if found), TOOLS USED, TOTAL SCAN TIME, SCAN DATE, SCAN TYPE
# INFORMATION TABLE
# TECHNOLOGIES FINGERPRINTED || TECHNOLOGY | VERSION | IS_VULNERABLE | CVE's
# VULNERABILITIES TABLE || Results should also be filtered with medium risk as to not overpopulate the table
# VULNERABILITIES || TYPE | CVE's | TOOL | ENDPOINT | CONFIDENCE | RISK
import os
import pandas as pd
from sqlalchemy.orm import Session
from sqlalchemy import select
import json

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from modules.db.database import Database
from modules.db.table_collection import Scan, TechDiscovery, Vulnerability
from modules.utils.load_configs import DEV_ENV

db = Database()


# FIX: Adjusted parsing logic for tech_discovery.data
def generate_excel(report_id: str):
    """
    Generates an Excel report from database results based on a report_id.

    The report is saved to the 'full_scan' reports directory.
    """
    file_name = f"Restack_Report_{report_id}.xlsx"
    output_path = os.path.join(DEV_ENV["report_paths"]["exports"], file_name)

    output_dir = os.path.dirname(output_path)
    os.makedirs(output_dir, exist_ok=True)

    with Session(db.engine) as session:
        scan_details = session.scalars(
            select(Scan).where(Scan.report_id == report_id)
        ).first()

        if not scan_details:
            return {"error": f"No scan details found for report_id: {report_id}"}

        # Initialize system details
        ip = "N/A"
        country = "N/A"
        server_os = "N/A"

        tech_list = []
        EXCLUDED_TECH = ["HTML", "HTML5"]

        # Fetch and process technology discovery data
        tech_discovery = session.scalars(
            select(TechDiscovery).where(TechDiscovery.report_id == report_id)
        ).first()

        if tech_discovery and tech_discovery.data:
            tech_data = tech_discovery.data
            if isinstance(tech_data, str):
                tech_data = json.loads(tech_data)

            # Data structure: [versioned, unversioned, cookies, extra]
            # Ensure we have enough elements
            if len(tech_data) >= 4:
                versioned_tech = tech_data[0]
                unversioned_tech = tech_data[1]
                # cookies = tech_data[2]
                extra_info = tech_data[3]

                # Process Versioned Tech
                for item in versioned_tech:
                    for tech, version in item.items():
                        if tech not in EXCLUDED_TECH:
                            # Handle version if it is a list
                            v_str = version[0] if isinstance(version, list) and version else str(version)
                            tech_list.append({"Technology": tech, "Version": v_str})

                # Process Unversioned Tech
                for item in unversioned_tech:
                    for tech, info in item.items():
                        if tech not in EXCLUDED_TECH:
                            tech_list.append({"Technology": tech, "Version": "N/A"})

                # Process Extra Info for System Details
                for item in extra_info:
                    for key, value in item.items():
                        # Handle value if it is a list
                        val_str = value[0] if isinstance(value, list) and value else str(value)

                        if key == "IP":
                            ip = val_str
                        elif key == "Country":
                            country = val_str
                        elif key == "HTTPServer":
                            server_os = val_str
            else:
                # Fallback for older/unexpected data structures
                pass

        # Create Scan Details DataFrame (Now includes System Info)
        scan_details_data = {
            "Scan Detail": [
                "Target URL",
                "Scan Type",
                "Scanner(s) Used",
                "Scan Date",
                "Total Scan Time (seconds)",
                "IP Address",
                "Country",
                "Server OS (if found)",
            ],
            "Value": [
                scan_details.target_url,
                scan_details.scan_type,
                scan_details.scanner,
                scan_details.scan_date.strftime("%Y-%m-%d %H:%M:%S"),
                scan_details.scan_duration,
                ip,
                country,
                server_os,
            ],
        }
        scan_df = pd.DataFrame(scan_details_data)

        tech_df = pd.DataFrame(tech_list)
        if tech_df.empty:
            tech_df = pd.DataFrame(columns=["Technology", "Version", "Vulnerable", "CVEs", "Fix"])

        vuln_results = session.scalars(
            select(Vulnerability).where(
                Vulnerability.report_id == report_id,
                Vulnerability.severity.in_(['Medium', 'High', 'Critical'])
            )
        ).all()

        vuln_list = []
        for v in vuln_results:
            vuln_list.append({
                "Type": v.vulnerability_type,
                "Risk": v.severity,
                "Confidence": v.confidence,
                "Scanner": v.scanner,
                "Endpoint": v.endpoint,
                "Description": v.description,
                "Fix": v.remediation_effort
            })

        vuln_df = pd.DataFrame(vuln_list)
        if vuln_df.empty:
            vuln_df = pd.DataFrame(columns=["Type", "Risk", "Confidence", "Scanner", "Endpoint", "Description", "Fix"])

        summary_data = {
            "Summary": [
                "AI Summary",
                "AI Recommendations",
            ],
            "Details": [
                "Feature not yet implemented. (modules/analytics/ai_recosum.py is a stub)",
                "Feature not yet implemented.",
            ]
        }
        summary_df = pd.DataFrame(summary_data)

        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            summary_df.to_excel(writer, sheet_name="Summary", index=False)
            scan_df.to_excel(writer, sheet_name="Scan Details", index=False)
            vuln_df.to_excel(writer, sheet_name="Vulnerabilities", index=False)
            tech_df.to_excel(writer, sheet_name="Technologies", index=False)

            for sheet_name in writer.sheets:
                worksheet = writer.sheets[sheet_name]
                for col in worksheet.columns:
                    max_length = 0
                    column = col[0].column_letter  # Get column name
                    for cell in col:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    adjusted_width = (max_length + 2)
                    worksheet.column_dimensions[column].width = adjusted_width

    return {"message": "Report generated successfully", "path": output_path}

def _add_header_footer(canvas, doc):
    """
    Adds a professional header and footer to every page for compliance.
    """
    canvas.saveState()

    # --- Header ---
    # Left: Report Name
    canvas.setFont('Helvetica-Bold', 10)
    canvas.setFillColor(colors.darkslategrey)
    canvas.drawString(inch, letter[1] - 0.5 * inch, "RESTACK REPORT")

    # Right: Classification Marking (Simulating Govt/Enterprise compliance)
    canvas.setFont('Helvetica-Bold', 10)
    canvas.setFillColor(colors.firebrick)  # Red often denotes sensitivity
    canvas.drawRightString(letter[0] - inch, letter[1] - 0.5 * inch, "CONFIDENTIAL // INTERNAL USE ONLY")

    # Line separator
    canvas.setStrokeColor(colors.lightgrey)
    canvas.setLineWidth(1)
    canvas.line(inch, letter[1] - 0.6 * inch, letter[0] - inch, letter[1] - 0.6 * inch)

    # --- Footer ---
    # Left: System Name
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(inch, 0.5 * inch, "Generated by Restack API")

    # Right: Page Number
    page_num = canvas.getPageNumber()
    canvas.drawRightString(letter[0] - inch, 0.5 * inch, f"Page {page_num}")

    canvas.restoreState()

def generate_pdf(report_id: str):
    """
    Generates a PDF report with overflow handling.
    """
    file_name = f"Restack_Report_{report_id}.pdf"
    output_path = os.path.join(DEV_ENV["report_paths"]["exports"], file_name)

    output_dir = os.path.dirname(output_path)
    os.makedirs(output_dir, exist_ok=True)

    # 1. Fetch Data
    with Session(db.engine) as session:
        scan_details = session.scalars(
            select(Scan).where(Scan.report_id == report_id)
        ).first()

        if not scan_details:
            return {"error": f"No scan details found for report_id: {report_id}"}

        # Initialize vars
        ip, country, server_os = "N/A", "N/A", "N/A"
        tech_list = [["Technology", "Version"]]
        EXCLUDED_TECH = ["HTML", "HTML5"]

        tech_discovery = session.scalars(
            select(TechDiscovery).where(TechDiscovery.report_id == report_id)
        ).first()

        if tech_discovery and tech_discovery.data:
            tech_data = tech_discovery.data
            if isinstance(tech_data, str):
                tech_data = json.loads(tech_data)

            if len(tech_data) >= 4:
                versioned_tech = tech_data[0]
                unversioned_tech = tech_data[1]
                extra_info = tech_data[3]

                for item in versioned_tech:
                    for tech, version in item.items():
                        if tech not in EXCLUDED_TECH:
                            v_str = version[0] if isinstance(version, list) and version else str(version)
                            tech_list.append([tech, v_str])

                for item in unversioned_tech:
                    for tech, info in item.items():
                        if tech not in EXCLUDED_TECH:
                            tech_list.append([tech, "N/A"])

                for item in extra_info:
                    for key, value in item.items():
                        val_str = value[0] if isinstance(value, list) and value else str(value)
                        if key == "IP":
                            ip = val_str
                        elif key == "Country":
                            country = val_str
                        elif key == "HTTPServer":
                            server_os = val_str

        vuln_results = session.scalars(
            select(Vulnerability).where(
                Vulnerability.report_id == report_id,
                Vulnerability.severity.in_(['Medium', 'High', 'Critical'])
            )
        ).all()

        vuln_count = len(vuln_results)

    # 2. Build PDF Document
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=inch, leftMargin=inch,
        topMargin=inch, bottomMargin=inch
    )
    elements = []
    styles = getSampleStyleSheet()

    # -- Custom Styles --
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        spaceAfter=20,
        textColor=colors.darkslategrey
    )
    h2_style = ParagraphStyle(
        'CustomH2',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.darkblue,
        spaceBefore=15,
        spaceAfter=10,
        borderPadding=5,
        borderColor=colors.lightgrey,
        borderWidth=0,
        borderBottomWidth=1
    )
    normal_style = styles['Normal']

    cell_style = ParagraphStyle(
        'CellStyle',
        parent=styles['Normal'],
        fontSize=9,
        leading=11
    )

    # -- Title Section --
    elements.append(Paragraph("Restack Report", title_style))
    elements.append(Paragraph(f"<b>Target:</b> {scan_details.target_url}", normal_style))
    elements.append(Paragraph(f"<b>Date:</b> {scan_details.scan_date.strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 20))

    # -- Summary Stub --
    elements.append(Paragraph("Summary", h2_style))
    elements.append(Paragraph("<b>AI Analysis:</b> Feature not yet implemented (Stub).", normal_style))
    elements.append(Spacer(1, 12))

    # -- Scan Details Table --
    elements.append(Paragraph("Scan Details & Environment", h2_style))
    scan_table_data = [
        ["Target URL", scan_details.target_url],
        ["Scan Date", scan_details.scan_date.strftime("%Y-%m-%d %H:%M:%S")],
        ["Duration", f"{scan_details.scan_duration} seconds"],
        ["Scanner Engine", scan_details.scanner],
        ["IP Address", ip],
        ["Hosted Country", country],
        ["Server OS", server_os],
        ["Vulnerabilities Found", f"{vuln_count} (Medium or higher)"]
    ]

    t_scan = Table(scan_table_data, colWidths=[180, 280])
    t_scan.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.whitesmoke),  # Light gray header column
        ('TEXTCOLOR', (0, 0), (0, -1), colors.darkslategrey),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
    ]))
    elements.append(t_scan)
    elements.append(Spacer(1, 12))

    # -- Technologies Table --
    if len(tech_list) > 1:
        elements.append(Paragraph("Fingerprinted Technologies", h2_style))
        t_tech = Table(tech_list, colWidths=[230, 230])
        t_tech.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkslategrey),  # Header Row
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.whitesmoke]),  # Striped rows
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_tech)
        elements.append(Spacer(1, 12))

    # -- Vulnerabilities Table --
    if len(vuln_results) > 0:
        elements.append(Paragraph("Detailed Vulnerability Findings", h2_style))
        elements.append(
            Paragraph("The following high-priority issues were detected during the automated scan.", normal_style))
        elements.append(Spacer(1, 6))

        table_body_data = []
        table_body_data.append(["Vulnerability Type", "Risk", "Conf.", "Endpoint"])  # Header

        for v in vuln_results:
            p_type = Paragraph(v.vulnerability_type, cell_style)

            endpoint_text = (v.endpoint[:60] + '..') if len(v.endpoint) > 60 else v.endpoint
            p_endpoint = Paragraph(endpoint_text, cell_style)

            table_body_data.append([p_type, v.severity, v.confidence, p_endpoint])

        t_vuln = Table(table_body_data, colWidths=[160, 50, 50, 200])
        t_vuln.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),  # Top align ensures clean look when text wraps
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.aliceblue]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_vuln)
    else:
        elements.append(Paragraph("No medium, high, or critical vulnerabilities detected.", normal_style))

    # -- Disclaimer --
    elements.append(Spacer(1, 30))
    disclaimer_style = ParagraphStyle('Disclaimer', parent=normal_style, fontSize=8, textColor=colors.grey,
                                      alignment=TA_CENTER)
    disclaimer_text = (
        "DISCLAIMER: This report is generated automatically by the Restack API. "
        "The results provided are for informational purposes only and do not represent a guarantee of security. "
    )
    elements.append(Paragraph(disclaimer_text, disclaimer_style))

    doc.build(elements, onFirstPage=_add_header_footer, onLaterPages=_add_header_footer)

    return {"message": "PDF Report generated successfully", "path": output_path}