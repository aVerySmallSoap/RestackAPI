from sqlalchemy.orm import Session
from sqlalchemy import func
from urllib.parse import urlparse

from modules.db.database import Database
from modules.db.table_collection import Vulnerability, Report, Scan


def pareto_vulnerability_analysis(target_domain: str = None):
    """
    Identify the 20% of vulnerability types causing 80% of issues
    Optionally filter by target domain
    """
    db = Database()
    engine = db.engine

    with Session(engine) as session:
        # Base query
        query = session.query(
            Vulnerability.vulnerability_type,
            func.count(Vulnerability.id).label('count')
        )

        # Apply domain filter if provided
        if target_domain:
            query = query.join(
                Report, Vulnerability.report_id == Report.id
            ).join(
                Scan, Report.id == Scan.report_id
            ).filter(
                Scan.target_url.like(f'%{target_domain}%')
            )

        # Get vulnerability type frequencies
        vuln_types = query.group_by(
            Vulnerability.vulnerability_type
        ).order_by(
            func.count(Vulnerability.id).desc()
        ).all()

        if not vuln_types:
            return {
                "error": "No vulnerability data found",
                "pareto_vulnerabilities": [],
                "insight": "No data available for analysis",
                "recommendation": "Perform scans to generate data"
            }

        total_vulns = sum(count for _, count in vuln_types)

        # Calculate cumulative percentage
        cumulative = 0
        pareto_data = []
        for vuln_type, count in vuln_types:
            cumulative += count
            cumulative_pct = (cumulative / total_vulns) * 100

            pareto_data.append({
                "vulnerability_type": vuln_type,
                "count": count,
                "percentage": (count / total_vulns) * 100,
                "cumulative_percentage": cumulative_pct
            })

            # Stop at 80% threshold
            if cumulative_pct >= 80:
                break

        result = {
            "pareto_vulnerabilities": pareto_data,
            "insight": f"Top {len(pareto_data)} vulnerability types account for 80% of all issues",
            "recommendation": "Focus remediation efforts on these high-impact vulnerability types"
        }

        if target_domain:
            result["filtered_by"] = target_domain
            result["total_vulnerabilities"] = total_vulns

        return result