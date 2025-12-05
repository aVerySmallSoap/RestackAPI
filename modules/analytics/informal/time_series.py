from datetime import datetime, timedelta
from sqlalchemy import select, and_  # Import and_
from sqlalchemy.orm import Session
from pydantic import AnyUrl

from modules.db.database import Database
from modules.db.table_collection import Report, Scan, Vulnerability


# Update signature to accept optional date strings
def calculate_time_series(target_url: AnyUrl, days: int = 90, start_date: str = None, end_date: str = None):
    """
    Generates time-series data. Supports explicit date range or 'last N days'.
    """
    db = Database()
    domain_str = target_url.host if target_url.host else str(target_url)

    with Session(db.engine) as session:
        # Base query: Join Report and Scan, filter by domain
        stmt = (
            select(Report)
            .join(Scan, Report.id == Scan.report_id)
            .where(Scan.target_url.ilike(f"%{domain_str}%"))
        )

        # Apply Date Filter
        if start_date and end_date:
            # Parse ISO strings (YYYY-MM-DD) passed from frontend
            s_date = datetime.strptime(start_date, "%Y-%m-%d")
            # Add one day to end_date to include the full day (since timestamps have time)
            e_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)

            stmt = stmt.where(and_(Report.scan_date >= s_date, Report.scan_date < e_date))
        else:
            # Fallback to simple 'days ago' logic
            cutoff_date = datetime.now() - timedelta(days=days)
            stmt = stmt.where(Report.scan_date >= cutoff_date)

        # Finalize order
        stmt = stmt.order_by(Report.scan_date)

        scans = session.scalars(stmt).all()

        timeseries_data = []

        for scan in scans:
            timeseries_data.append({
                "date": scan.scan_date.strftime("%Y-%m-%d %H:%M"),
                "count": scan.total_vulnerabilities,
                "critical_count": scan.critical_count,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "scan_type": scan.scan_type
            })

    return timeseries_data