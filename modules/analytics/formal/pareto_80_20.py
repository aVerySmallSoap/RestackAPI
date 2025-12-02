import pprint

from sqlalchemy.orm import Session
from sqlalchemy import func

from modules.db.database import Database
from modules.db.table_collection import Vulnerability

def pareto_vulnerability_analysis():
    """
    Identify the 20% of vulnerability types causing 80% of issues
    """
    db = Database()
    engine = db.engine

    with Session(engine) as session:
        # Get vulnerability type frequencies
        vuln_types = session.query(
            Vulnerability.vulnerability_type,
            func.count(Vulnerability.id).label('count')
        ).group_by(Vulnerability.vulnerability_type
                   ).order_by(func.count(Vulnerability.id).desc()).all()

        # sample = session.query(
        #     Vulnerability.vulnerability_type,
        #     func.count(Vulnerability.id).label('count')
        # ).filter(Vulnerability.report_id == report_id)

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

        return {
            "pareto_vulnerabilities": pareto_data,
            "insight": f"Top {len(pareto_data)} vulnerability types account for 80% of all issues",
            "recommendation": "Focus remediation efforts on these high-impact vulnerability types"
        }