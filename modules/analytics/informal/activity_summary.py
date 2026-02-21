from datetime import datetime, timedelta
from sqlalchemy.orm.session import Session
from sqlalchemy import func
from modules.db.database import Database
from modules.db.table_collection import Scan, Report

def get_scan_activity_summary(days: int = 30, target_domain: str = None):
    """
    Overall scanning activity and coverage metrics.
    Optionally filter by target_domain.
    """
    db = Database()
    engine = db.engine
    cutoff_date = datetime.now() - timedelta(days=days)

    with Session(engine) as session:
        # --- Helper to apply target filter ---
        def apply_filter(query, model):
            if not target_domain:
                return query
            if model == Scan:
                return query.filter(Scan.target_url.like(f'%{target_domain}%'))
            if model == Report:
                return query.join(Scan, Report.id == Scan.report_id).filter(
                    Scan.target_url.like(f'%{target_domain}%')
                )
            return query

        # 1. Total Scans
        q = session.query(func.count(Report.id)).filter(Report.scan_date >= cutoff_date)
        total_scans = apply_filter(q, Report).scalar() or 0

        # 2. Unique Targets
        q = session.query(func.count(func.distinct(Scan.target_url))).filter(Scan.scan_date >= cutoff_date)
        unique_targets = apply_filter(q, Scan).scalar() or 0

        # 3. Total Vulnerabilities
        q = session.query(func.sum(Report.total_vulnerabilities)).filter(Report.scan_date >= cutoff_date)
        total_vulns = apply_filter(q, Report).scalar() or 0

        # 4. Scan Type Distribution
        q = session.query(Report.scan_type, func.count(Report.id)).filter(Report.scan_date >= cutoff_date)
        scan_types = apply_filter(q, Report).group_by(Report.scan_type).all()

        # 5. Average Duration
        q = session.query(Scan.scan_type, func.avg(Scan.scan_duration)).filter(Scan.scan_date >= cutoff_date)
        avg_durations = apply_filter(q, Scan).group_by(Scan.scan_type).all()

        # 6. Daily Activity
        q = session.query(func.date(Report.scan_date).label('date'), func.count(Report.id)).filter(Report.scan_date >= cutoff_date)
        daily_activity = apply_filter(q, Report).group_by('date').order_by('date').all()

        # 7. Top Targets
        q = session.query(Scan.target_url, func.count(Scan.id)).filter(Scan.scan_date >= cutoff_date)
        top_targets = apply_filter(q, Scan).group_by(Scan.target_url).order_by(func.count(Scan.id).desc()).limit(5).all()

        return {
            "period_days": days,
            "filter": target_domain or "all",
            "summary_statistics": {
                "total_scans": total_scans,
                "unique_targets": unique_targets,
                "total_vulnerabilities_found": total_vulns,
                "average_vulns_per_scan": (total_vulns / total_scans) if total_scans > 0 else 0,
                "scans_per_day": round(total_scans / days, 2)
            },
            "scan_type_distribution": {t: c for t, c in scan_types},
            "average_scan_duration": {t: float(d) for t, d in avg_durations},
            "daily_activity": [{"date": str(d), "count": c} for d, c in daily_activity],
            "most_scanned_targets": [{"url": u, "scan_count": c} for u, c in top_targets]
        }