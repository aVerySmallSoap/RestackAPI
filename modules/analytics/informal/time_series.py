from datetime import datetime, timedelta
from sqlalchemy import select
from sqlalchemy.orm import Session
from pydantic import AnyUrl  # Import AnyUrl for type hinting

from modules.db.database import Database
from modules.db.table_collection import Report, Scan, Vulnerability


def calculate_time_series(target_url: AnyUrl, days: int = 90):
    """
    Generates time-series data for a specific target.
    Accepts Pydantic AnyUrl and extracts the host for broader database matching.
    """
    db = Database()

    # FIX: Extract the host string (e.g., "example.com") from the AnyUrl object
    # This allows 'http://example.com' to match 'https://example.com' in the DB
    domain_str = target_url.host if target_url.host else str(target_url)

    with Session(db.engine) as session:
        cutoff_date = datetime.now() - timedelta(days=days)

        stmt = (
            select(Report)
            .join(Scan, Report.id == Scan.report_id)
            .where(
                # Use ilike with the extracted domain string
                Scan.target_url.ilike(f"%{domain_str}%"),
                Report.scan_date >= cutoff_date
            )
            .order_by(Report.scan_date)
        )

        scans = session.scalars(stmt).all()

        timeseries_data = []

        for scan in scans:
            # Generate the data point
            timeseries_data.append({
                "date": scan.scan_date.strftime("%Y-%m-%d %H:%M"),
                "count": scan.total_vulnerabilities,
                "critical_count": scan.critical_count,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "scan_type": scan.scan_type
            })

    return timeseries_data