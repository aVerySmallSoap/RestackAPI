from datetime import datetime, timedelta

from sqlalchemy.orm.session import Session

from modules.db.database import Database
from modules.db.table_collection import Report, Scan, Vulnerability

db = Database()
engine = db.engine
test_url = "http://example.com/"

with Session(engine) as session:
    cutoff_date = datetime.now() - timedelta(days=30)

    scans = session.query(Report).join(
        Scan, Report.id == Scan.report_id
    ).filter(
        Scan.target_url == test_url,
        Report.scan_date >= cutoff_date
    ).order_by(Report.scan_date).all()

    timeseries_data = []
    for scan in scans:
        vulns = session.query(Vulnerability).filter(
            Vulnerability.report_id == scan.id
        ).all()

        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        }

        for vuln in vulns:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

        timeseries_data.append({
            "date": scan.scan_date.strftime("%Y-%m-%d"),
            "total_vulnerabilities": scan.total_vulnerabilities,
            "critical_count": scan.critical_count,
            "severity_breakdown": severity_counts,
            "scan_type": scan.scan_type
        })

        if len(timeseries_data) >= 2:
            trend = "increasing" if timeseries_data[-1]["total_vulnerabilities"] > timeseries_data[0]["total_vulnerabilities"] else "decreasing"
        else:
            trend = "insufficient data"

print({
    "target_url": test_url,
    "period_days": 30,
    "scan_count": len(timeseries_data),
    "trend": trend,
    "current_total": timeseries_data[-1]["total_vulnerabilities"] if timeseries_data else 0,
    "previous_total": timeseries_data[0]["total_vulnerabilities"] if timeseries_data else 0
})