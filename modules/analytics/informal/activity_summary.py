import pprint
from datetime import datetime, timedelta

from sqlalchemy.orm.session import Session
from sqlalchemy import func

from modules.db.database import Database
from modules.db.table_collection import Vulnerability, Scan, Report


def get_scan_activity_summary(days: int = 30):
    """Overall scanning activity and coverage metrics"""
    db = Database()
    engine = db.engine
    cutoff_date = datetime.now() - timedelta(days=days)

    with Session(engine) as session:
        # Basic scan statistics
        total_scans = session.query(func.count(Report.id)).filter(
            Report.scan_date >= cutoff_date
        ).scalar()

        # Unique targets scanned
        unique_targets = session.query(
            func.count(func.distinct(Scan.target_url))
        ).filter(
            Scan.scan_date >= cutoff_date
        ).scalar()

        # Scan type distribution
        scan_types = session.query(
            Report.scan_type,
            func.count(Report.id).label('count')
        ).filter(
            Report.scan_date >= cutoff_date
        ).group_by(Report.scan_type).all()

        # Average scan duration by type
        avg_durations = session.query(
            Scan.scan_type,
            func.avg(Scan.scan_duration).label('avg_duration')
        ).filter(
            Scan.scan_date >= cutoff_date
        ).group_by(Scan.scan_type).all()

        # Total vulnerabilities found
        total_vulns = session.query(
            func.count(Vulnerability.id)
        ).filter(
            Vulnerability.scan_date >= cutoff_date
        ).scalar()

        # Scans by day (for trend visualization)
        daily_scans = session.query(
            func.date(Report.scan_date).label('date'),
            func.count(Report.id).label('count')
        ).filter(
            Report.scan_date >= cutoff_date
        ).group_by(func.date(Report.scan_date)).order_by('date').all()

        # Most scanned targets
        top_targets = session.query(
            Scan.target_url,
            func.count(Scan.id).label('scan_count')
        ).filter(
            Scan.scan_date >= cutoff_date
        ).group_by(Scan.target_url).order_by(
            func.count(Scan.id).desc()
        ).limit(5).all()

        return {
            "period_days": days,
            "summary_statistics": {
                "total_scans": total_scans,
                "unique_targets": unique_targets,
                "total_vulnerabilities_found": total_vulns,
                "average_vulns_per_scan": total_vulns / total_scans if total_scans > 0 else 0,
                "scans_per_day": total_scans / days
            },
            "scan_type_distribution": {
                scan_type: count for scan_type, count in scan_types
            },
            "average_scan_duration": {
                scan_type: float(avg_dur) for scan_type, avg_dur in avg_durations
            },
            "daily_activity": [
                {"date": date.strftime("%Y-%m-%d"), "count": count}
                for date, count in daily_scans
            ],
            "most_scanned_targets": [
                {"url": url, "scan_count": count}
                for url, count in top_targets
            ]
        }

pprint.pprint(get_scan_activity_summary(days=30))