#Future feature
import pprint
from datetime import datetime, timedelta

from requests.sessions import Session

from modules.db.table_collection import Report
from services.FileReportGenerator import db


def get_vulnerability_trend(target_url: str, days: int = 30):
    """Get vulnerability counts over time for a target"""
    engine = db.engine
    with Session(engine) as session:
        scans = session.query(Report).filter(
            Report.target_url == target_url,
            Report.scan_date >= datetime.now() - timedelta(days=days)
        ).order_by(Report.scan_date).all()

        return [{
            "date": s.scan_date,
            "total": s.total_vulnerabilities,
            "critical": s.critical_count
        } for s in scans]