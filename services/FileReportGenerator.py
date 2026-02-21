# Generate reports based on system results
# Outputs: PDF and Excel
#
# STRUCTURE
#   NUMBER OF VULNERABILITIES DETECTED  (filtered: Medium risk and above)
#   AI SUMMARY OF RESULTS
#   AI RECOMMENDATIONS BASED ON RESULTS
#   SCAN DETAILS       — Domain, IP, Server OS, Tools, Total Scan Time, Scan Date, Scan Type
#   TECHNOLOGIES TABLE — Technology | Version | CVEs
#   VULNERABILITIES    — Type | Tool | Endpoint | Confidence | Risk
#                        (filtered: Medium risk and above)

import html
import json
import os
import re

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from modules.db.database import Database
from modules.db.table_collection import Report, Scan, TechDiscovery, Vulnerability
from modules.utils.load_configs import DEV_ENV

db = Database()

# Severities that qualify as "medium risk and above"
RISK_FILTER = ["Medium", "High", "Critical"]

# Technologies to suppress from output (too generic to be useful)
EXCLUDED_TECH = ["HTML", "HTML5"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_for_pdf(text: str) -> str:
    """
    Sanitize arbitrary text (e.g. Gemini markdown output) so ReportLab's
    paragraph parser won't choke on it.

    Steps:
      1. Strip HTML/XML tags entirely — ReportLab only supports its own small
         tag subset, and foreign tags like <link rel=...> cause hard crashes.
      2. Escape any remaining angle-bracket characters so they render as
         literal text rather than being parsed as markup.
      3. Convert the most common markdown constructs to ReportLab-safe RML:
           **bold**  → <b>bold</b>
           `code`    → code  (backticks removed, ReportLab has no <code> tag)
           ### Head  → newline + bold heading line
           ---       → removed (horizontal rules not supported in Paragraph)
      4. Collapse excess whitespace / blank lines.
    """
    if not text:
        return ""

    # 1. Remove raw HTML tags (anything that looks like <tag ...>)
    text = re.sub(r"<[^>]+>", "", text)

    # 2. Escape residual < > & so they don't confuse ReportLab's XML parser
    text = html.escape(text, quote=False)

    # 3. Markdown → RML conversions (order matters)
    # Bold: **text** or __text__
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"__(.+?)__",     r"<b>\1</b>", text)
    # Italic: *text* or _text_  (single — avoid touching already-converted <b> tags)
    text = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<i>\1</i>", text)
    # Inline code: `code`
    text = re.sub(r"`([^`]+)`", r"\1", text)
    # Fenced code blocks: ```...```
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    # ATX headings: ## Heading  →  bold line
    text = re.sub(r"^#{1,6}\s+(.+)$", r"\n<b>\1</b>", text, flags=re.MULTILINE)
    # Horizontal rules
    text = re.sub(r"^-{3,}$", "", text, flags=re.MULTILINE)
    # Bullet points: * item or - item  (keep text, strip the bullet marker)
    text = re.sub(r"^\s*[\*\-]\s+", "  • ", text, flags=re.MULTILINE)
    # Numbered lists: 1. item  (keep as-is — already readable)

    # 4. Collapse 3+ consecutive newlines to 2
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()

def _safe_str(value) -> str:
    """Return the first element if value is a list, else str(value)."""
    if isinstance(value, list):
        return value[0] if value else "N/A"
    return str(value) if value is not None else "N/A"


def _extract_cves(data: dict | None) -> str:
    """
    Try common key names for CVE lists stored in a vulnerability's data JSON.
    Returns a comma-separated string or 'N/A'.
    """
    if not data or not isinstance(data, dict):
        return "N/A"
    for key in ("cves", "cve", "CVEs", "CVE", "cve_ids"):
        val = data.get(key)
        if val:
            if isinstance(val, list):
                return ", ".join(str(v) for v in val)
            return str(val)
    return "N/A"


def _parse_tech_discovery(tech_discovery) -> tuple[list[dict], str, str, str]:
    """
    Parse a TechDiscovery ORM object.

    Returns:
        tech_list  – list of dicts with keys Technology, Version
        ip         – IP address string or 'N/A'
        country    – country string or 'N/A'
        server_os  – HTTP server / OS string or 'N/A'
    """
    tech_list: list[dict] = []
    ip = country = server_os = "N/A"

    if not (tech_discovery and tech_discovery.data):
        return tech_list, ip, country, server_os

    tech_data = tech_discovery.data
    if isinstance(tech_data, str):
        tech_data = json.loads(tech_data)

    # Expected structure: [versioned, unversioned, cookies, extra]
    if len(tech_data) < 4:
        return tech_list, ip, country, server_os

    versioned_tech, unversioned_tech, _cookies, extra_info = (
        tech_data[0], tech_data[1], tech_data[2], tech_data[3]
    )

    for item in versioned_tech:
        for tech, version in item.items():
            if tech not in EXCLUDED_TECH:
                tech_list.append({"Technology": tech, "Version": _safe_str(version)})

    for item in unversioned_tech:
        for tech in item.keys():
            if tech not in EXCLUDED_TECH:
                tech_list.append({"Technology": tech, "Version": "N/A"})

    for item in extra_info:
        for key, value in item.items():
            val = _safe_str(value)
            if key == "IP":
                ip = val
            elif key == "Country":
                country = val
            elif key == "HTTPServer":
                server_os = val

    return tech_list, ip, country, server_os


def _serialise_vulns(vuln_results) -> list[dict]:
    """Convert SQLAlchemy Vulnerability rows into plain dicts (safe outside session)."""
    rows = []
    for v in vuln_results:
        rows.append({
            "Type":        v.vulnerability_type,
            "Risk":        v.severity,
            "Confidence":  v.confidence,
            "Scanner":     v.scanner,
            "Endpoint":    v.endpoint,
            "Description": v.description,
            "Fix":         v.remediation_effort,
            "CVEs":        _extract_cves(v.data if isinstance(v.data, dict) else {}),
        })
    return rows


# ---------------------------------------------------------------------------
# Excel
# ---------------------------------------------------------------------------

def generate_excel(report_id: str) -> dict:
    """
    Generate an Excel workbook for the given report_id.
    Sheets: Summary | Scan Details | Vulnerabilities | Technologies
    """
    file_name = f"Restack_Report_{report_id}.xlsx"
    output_path = os.path.join(DEV_ENV["report_paths"]["exports"], file_name)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with Session(db.engine) as session:
        # -- Scan --
        scan = session.scalars(
            select(Scan).where(Scan.report_id == report_id)
        ).first()
        if not scan:
            return {"error": f"No scan found for report_id: {report_id}"}

        # -- Report (for AI summaries) --
        report = session.scalars(
            select(Report).where(Report.id == report_id)
        ).first()

        # -- Technologies --
        tech_discovery = session.scalars(
            select(TechDiscovery).where(TechDiscovery.report_id == report_id)
        ).first()
        tech_list, ip, country, server_os = _parse_tech_discovery(tech_discovery)

        # -- Vulnerabilities --
        vuln_rows = session.scalars(
            select(Vulnerability).where(
                Vulnerability.report_id == report_id,
                Vulnerability.severity.in_(RISK_FILTER),
                Vulnerability.is_duplicate.is_(False),
            )
        ).all()
        vulns = _serialise_vulns(vuln_rows)

        # -- AI summary text --
        ai_vuln_summary = (
            report.ai_summary_vulnerabilities
            if report and report.ai_summary_vulnerabilities
            else "AI summary not yet available."
        )
        ai_tech_summary = (
            report.ai_summary_tech
            if report and report.ai_summary_tech
            else "AI technology summary not yet available."
        )

    # Build DataFrames
    # Excel cells can hold raw text — no need to sanitize for ReportLab here.
    summary_df = pd.DataFrame({
        "Category": ["Vulnerability Summary", "Technology Summary"],
        "AI Analysis": [ai_vuln_summary, ai_tech_summary],
    })

    scan_df = pd.DataFrame({
        "Scan Detail": [
            "Target URL", "Scan Type", "Scanner(s) Used", "Scan Date",
            "Total Scan Time (seconds)", "Crawl Depth",
            "IP Address", "Country", "Server / OS",
            "Vulnerabilities Found (Medium+)",
        ],
        "Value": [
            scan.target_url, scan.scan_type, scan.scanner,
            scan.scan_date.strftime("%Y-%m-%d %H:%M:%S"),
            scan.scan_duration, scan.crawl_depth,
            ip, country, server_os,
            len(vulns),
        ],
    })

    vuln_df = pd.DataFrame(vulns) if vulns else pd.DataFrame(
        columns=["Type", "Risk", "Confidence", "Scanner", "Endpoint", "Description", "Fix", "CVEs"]
    )

    tech_df = pd.DataFrame(tech_list) if tech_list else pd.DataFrame(
        columns=["Technology", "Version"]
    )

    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        for df, sheet in [
            (summary_df, "Summary"),
            (scan_df,    "Scan Details"),
            (vuln_df,    "Vulnerabilities"),
            (tech_df,    "Technologies"),
        ]:
            df.to_excel(writer, sheet_name=sheet, index=False)

        # Auto-fit column widths
        for sheet_name, worksheet in writer.sheets.items():
            for col in worksheet.columns:
                max_len = max(
                    (len(str(cell.value)) for cell in col if cell.value is not None),
                    default=10,
                )
                worksheet.column_dimensions[col[0].column_letter].width = min(max_len + 4, 80)

    return {"message": "Excel report generated successfully", "path": output_path}


# ---------------------------------------------------------------------------
# PDF helpers
# ---------------------------------------------------------------------------

def _footer_only(canvas, doc):
    """Footer: thin rule with 'Restack' on the left, page number on the right."""
    canvas.saveState()
    # Thin rule above footer text
    canvas.setStrokeColor(colors.HexColor("#CCCCCC"))
    canvas.setLineWidth(0.5)
    canvas.line(inch, 0.6 * inch, letter[0] - inch, 0.6 * inch)
    # Left: branding
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#888888"))
    canvas.drawString(inch, 0.4 * inch, "Restack Report")
    # Right: page number
    canvas.drawRightString(letter[0] - inch, 0.4 * inch, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


def _plain_table_style(header_row: bool = True) -> TableStyle:
    """
    Clean modern table: light gray header, no outer border, subtle inner lines.
    """
    ACCENT     = colors.HexColor("#2C3E50")  # dark slate — headings / header text
    HEADER_BG  = colors.HexColor("#F2F4F5")  # very light gray header background
    GRID_COLOR = colors.HexColor("#DDDDDD")  # soft grid lines

    base = [
        ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("LEADING",       (0, 0), (-1, -1), 13),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        # Only inner horizontal lines — cleaner than a full grid
        ("LINEBELOW",     (0, 0), (-1, -2), 0.4, GRID_COLOR),
        # Outer box
        ("BOX",           (0, 0), (-1, -1), 0.5, GRID_COLOR),
    ]
    if header_row:
        base += [
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
            ("TEXTCOLOR",  (0, 0), (-1, 0), ACCENT),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, 0), 8.5),
            ("LINEBELOW",  (0, 0), (-1, 0), 1, ACCENT),
        ]
    return TableStyle(base)


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def generate_pdf(report_id: str) -> dict:
    """
    Generate a minimal, print-ready PDF report for the given report_id.
    """
    file_name = f"Restack_Report_{report_id}.pdf"
    output_path = os.path.join(DEV_ENV["report_paths"]["exports"], file_name)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # ------------------------------------------------------------------
    # 1. Fetch all data inside a single session, serialise immediately
    # ------------------------------------------------------------------
    with Session(db.engine) as session:
        scan = session.scalars(
            select(Scan).where(Scan.report_id == report_id)
        ).first()
        if not scan:
            return {"error": f"No scan found for report_id: {report_id}"}

        report = session.scalars(
            select(Report).where(Report.id == report_id)
        ).first()
        # (Report fetched for future use; AI summaries are PDF-excluded — see Excel only)

        tech_discovery = session.scalars(
            select(TechDiscovery).where(TechDiscovery.report_id == report_id)
        ).first()
        tech_list, ip, country, server_os = _parse_tech_discovery(tech_discovery)

        vuln_rows = session.scalars(
            select(Vulnerability).where(
                Vulnerability.report_id == report_id,
                Vulnerability.severity.in_(RISK_FILTER),
                Vulnerability.is_duplicate.is_(False),
            )
        ).all()
        vulns = _serialise_vulns(vuln_rows)  # plain dicts — safe after session closes

        # Snapshot scalar fields before session closes
        target_url   = scan.target_url
        scan_date    = scan.scan_date.strftime("%Y-%m-%d %H:%M:%S")
        scan_type    = scan.scan_type
        scanner      = scan.scanner
        duration     = scan.scan_duration
        crawl_depth  = scan.crawl_depth

    # ------------------------------------------------------------------
    # 2. Styles
    # ------------------------------------------------------------------
    ACCENT = colors.HexColor("#2C3E50")

    styles = getSampleStyleSheet()

    style_title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=26,
        spaceAfter=2,
        textColor=ACCENT,
        alignment=TA_LEFT,
        fontName="Helvetica-Bold",
    )
    style_meta = ParagraphStyle(
        "ReportMeta",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#555555"),
        spaceAfter=3,
    )
    style_h2 = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=11,
        leading=14,
        textColor=ACCENT,
        spaceBefore=20,
        spaceAfter=6,
        fontName="Helvetica-Bold",
    )
    style_body = ParagraphStyle(
        "BodyText",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#333333"),
    )
    style_cell = ParagraphStyle(
        "CellText",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#333333"),
    )
    style_disclaimer = ParagraphStyle(
        "Disclaimer",
        parent=styles["Normal"],
        fontSize=7,
        leading=10,
        textColor=colors.HexColor("#999999"),
        alignment=TA_CENTER,
    )

    def hr():
        return HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#DDDDDD"), spaceAfter=8)

    def accent_hr():
        """Thicker rule in accent color — used once under the title."""
        return HRFlowable(width="100%", thickness=1.5, color=ACCENT, spaceAfter=10)

    # ------------------------------------------------------------------
    # 3. Build elements
    # ------------------------------------------------------------------
    elements = []

    # Title block
    elements.append(Paragraph("Restack Report", style_title))
    elements.append(accent_hr())
    elements.append(Paragraph(f"<b>Target:</b> {target_url}", style_meta))
    elements.append(Paragraph(f"<b>Date:</b> {scan_date}", style_meta))
    elements.append(Paragraph(f"<b>Issues found:</b> {len(vulns)}", style_meta))
    elements.append(Spacer(1, 16))

    # -- Scan Details --
    elements.append(Paragraph("Scan Info", style_h2))
    elements.append(hr())

    scan_table_data = [
        ["",                   ""],
        ["Website",            target_url],
        ["Scan Date",          scan_date],
        ["Scan Type",          scan_type],
        ["Tools Used",         scanner],
        ["Time Taken",         f"{duration}s"],
        ["Crawl Depth",        str(crawl_depth)],
        ["IP Address",         ip],
        ["Country",            country],
        ["Server",             server_os],
        ["Issues Found",       str(len(vulns))],
    ]

    t_scan = Table(scan_table_data, colWidths=[170, 300])
    t_scan.setStyle(_plain_table_style(header_row=True))
    elements.append(t_scan)

    # -- Technologies --
    if tech_list:
        elements.append(Paragraph("Technologies Detected", style_h2))
        elements.append(hr())

        tech_cve_map: dict[str, set] = {}
        for v in vulns:
            if v["CVEs"] != "N/A":
                for tech_entry in tech_list:
                    tech_name = tech_entry["Technology"].lower()
                    if tech_name in v["Type"].lower() or tech_name in v["Description"].lower():
                        tech_cve_map.setdefault(tech_entry["Technology"], set()).update(
                            c.strip() for c in v["CVEs"].split(",")
                        )

        tech_table_data = [["Technology", "Version", "Known CVEs"]]
        for entry in tech_list:
            cves = ", ".join(sorted(tech_cve_map.get(entry["Technology"], set()))) or "None"
            tech_table_data.append([
                Paragraph(entry["Technology"], style_cell),
                Paragraph(entry["Version"], style_cell),
                Paragraph(cves, style_cell),
            ])

        t_tech = Table(tech_table_data, colWidths=[160, 90, 220])
        t_tech.setStyle(_plain_table_style(header_row=True))
        elements.append(t_tech)

    # -- Vulnerabilities --
    elements.append(Paragraph("Issues Found", style_h2))
    elements.append(hr())

    if vulns:
        elements.append(Paragraph(
            f"{len(vulns)} issue(s) detected — medium severity and above.",
            style_body,
        ))
        elements.append(Spacer(1, 6))

        vuln_table_data = [["Issue", "Severity", "Confidence", "Tool", "URL"]]
        for v in vulns:
            endpoint_display = v["Endpoint"]
            if len(endpoint_display) > 55:
                endpoint_display = endpoint_display[:52] + "..."
            vuln_table_data.append([
                Paragraph(v["Type"],        style_cell),
                Paragraph(v["Risk"],        style_cell),
                Paragraph(v["Confidence"],  style_cell),
                Paragraph(v["Scanner"],     style_cell),
                Paragraph(endpoint_display, style_cell),
            ])

        t_vuln = Table(vuln_table_data, colWidths=[130, 48, 60, 70, 162])
        t_vuln.setStyle(_plain_table_style(header_row=True))
        elements.append(t_vuln)
    else:
        elements.append(Paragraph(
            "No issues of medium severity or above were found.", style_body
        ))

    # -- Disclaimer --
    elements.append(Spacer(1, 30))
    elements.append(hr())
    elements.append(Paragraph(
        "Auto-generated by Restack. Results are for reference only. Always verify with a professional.",
        style_disclaimer,
    ))

    # ------------------------------------------------------------------
    # 4. Build
    # ------------------------------------------------------------------
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=inch,
        leftMargin=inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    doc.build(elements, onFirstPage=_footer_only, onLaterPages=_footer_only)

    return {"message": "PDF report generated successfully", "path": output_path}