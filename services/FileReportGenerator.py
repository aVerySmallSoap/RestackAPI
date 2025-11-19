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

from modules.db.database import Database
from modules.db.table_collection import Scan, TechDiscovery, Vulnerability
from modules.utils.load_configs import DEV_ENV

db = Database()


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

        scan_details_data = {
            "Scan Detail": [
                "Target URL",
                "Scan Type",
                "Scanner(s) Used",
                "Scan Date",
                "Total Scan Time (seconds)",
            ],
            "Value": [
                scan_details.target_url,
                scan_details.scan_type,
                scan_details.scanner,
                scan_details.scan_date.strftime("%Y-%m-%d %H:%M:%S"),
                scan_details.scan_duration,
            ],
        }
        scan_df = pd.DataFrame(scan_details_data)

        tech_discovery = session.scalars(
            select(TechDiscovery).where(TechDiscovery.report_id == report_id)
        ).first()

        tech_list = []
        if tech_discovery and tech_discovery.data:

            tech_data = tech_discovery.data
            if isinstance(tech_data, str):
                tech_data = json.loads(tech_data)

            versioned_tech = tech_discovery.data[0]
            unversioned_tech = tech_discovery.data[1]

            for item in versioned_tech:
                for tech, version in item.items():
                    tech_list.append({"Technology": tech, "Version": version})
            for item in unversioned_tech:
                for tech, info in item.items():
                    tech_list.append({"Technology": tech, "Version": "N/A"})

        tech_df = pd.DataFrame(tech_list)
        if tech_df.empty:
            tech_df = pd.DataFrame(columns=["Technology", "Version"])

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
            })

        vuln_df = pd.DataFrame(vuln_list)
        if vuln_df.empty:
            vuln_df = pd.DataFrame(columns=["Type", "Risk", "Confidence", "Scanner", "Endpoint", "Description"])


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


def generate_pdf(report_id: str):
    """
    Generates a PDF report.

    NOTE: This requires a PDF generation library like reportlab or fpdf2
    which is not currently listed in requirements.txt.
    """
    # TODO: Add a PDF library to requirements.txt (e.g., 'pip install reportlab')
    # Then, implement PDF generation logic here, likely using data
    # fetched similarly to 'generate_excel'.
    pass