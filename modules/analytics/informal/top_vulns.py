from sqlalchemy.orm import Session
from sqlalchemy import func
from modules.db.database import Database
from modules.db.table_collection import Vulnerability


def get_top_vulnerable_endpoints(report_id: str = None, limit: int = 10):
    """Identify endpoints with the most vulnerabilities"""
    db = Database()
    engine = db.engine

    with Session(engine) as session:
        query = session.query(
            Vulnerability.endpoint,
            func.count(Vulnerability.id).label('vuln_count'),
            func.sum(
                func.case(
                    (Vulnerability.severity == 'Critical', 1),
                    (Vulnerability.severity == 'High', 1),
                    else_=0
                )
            ).label('critical_high_count')
        )

        if report_id:
            query = query.filter(Vulnerability.report_id == report_id)

        results = query.group_by(
            Vulnerability.endpoint
        ).order_by(
            func.count(Vulnerability.id).desc()
        ).limit(limit).all()

        endpoint_data = []
        for endpoint, vuln_count, critical_high_count in results:
            # Get severity breakdown for this endpoint
            severity_breakdown = session.query(
                Vulnerability.severity,
                func.count(Vulnerability.id).label('count')
            ).filter(
                Vulnerability.endpoint == endpoint
            )

            if report_id:
                severity_breakdown = severity_breakdown.filter(
                    Vulnerability.report_id == report_id
                )

            severity_breakdown = severity_breakdown.group_by(
                Vulnerability.severity
            ).all()

            endpoint_data.append({
                "endpoint": endpoint,
                "total_vulnerabilities": vuln_count,
                "critical_high_count": critical_high_count or 0,
                "severity_breakdown": {
                    severity: count for severity, count in severity_breakdown
                },
                "risk_score": (critical_high_count or 0) * 10 + vuln_count
            })

        return {
            "top_vulnerable_endpoints": endpoint_data,
            "total_unique_endpoints": session.query(
                func.count(func.distinct(Vulnerability.endpoint))
            ).scalar()
        }