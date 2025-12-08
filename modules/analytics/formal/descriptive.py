from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy import select, func, and_, desc
from sqlalchemy.orm import Session
import pandas as pd
import numpy as np

from modules.db.table_collection import Report, Scan, Vulnerability


def get_general_analytics(
        session: Session,
        target_domain: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None
) -> Dict[str, Any]:
    """
    Standardized Analytics Endpoint for Visualizations.
    """

    # 1. DATE FILTER LOGIC
    if start_date and end_date:
        try:
            s_date = datetime.strptime(start_date, "%Y-%m-%d")
            e_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            cutoff_filter = and_(Report.scan_date >= s_date, Report.scan_date < e_date)
        except ValueError:
            return {"error": "Invalid date format. Use YYYY-MM-DD"}
    else:
        # Default 90 Days
        cutoff_date = datetime.now() - timedelta(days=90)
        cutoff_filter = Report.scan_date >= cutoff_date

    # 2. FETCH HISTORY
    stmt = select(Report).join(Scan, Report.id == Scan.report_id).where(cutoff_filter)

    if target_domain and target_domain != 'all':
        stmt = stmt.where(Scan.target_url.ilike(f"%{target_domain}%"))

    reports = session.scalars(stmt).unique().all()

    if not reports:
        return {"error": "No data available"}

    # 3. STATISTICAL ANALYSIS (Stability & Trend)
    history_data = []
    for r in reports:
        history_data.append({
            "date": r.scan_date.strftime("%Y-%m-%d"),
            "timestamp": r.scan_date.timestamp(),
            "Total": r.total_vulnerabilities,
            "Critical": r.critical_count
        })

    df = pd.DataFrame(history_data).sort_values('timestamp')

    stability_score = 0
    trend_direction = "Flat"

    if len(df) > 1:
        # Stability (CV)
        mean = df['Total'].mean()
        std = df['Total'].std()
        cov = std / mean if mean > 0 else 0
        stability_score = max(0, int(100 - (cov * 100)))

        # Trend (Slope)
        if len(df) >= 3:
            slope, _ = np.polyfit(range(len(df)), df['Total'], 1)
            if slope < -0.1:
                trend_direction = "Decreasing"
            elif slope > 0.1:
                trend_direction = "Increasing"

    # 4. SNAPSHOT ANALYSIS
    latest_report = sorted(reports, key=lambda x: x.scan_date)[-1]

    # A. Severity Distribution
    sev_counts = session.query(
        Vulnerability.severity, func.count(Vulnerability.id)
    ).filter(
        Vulnerability.report_id == latest_report.id
    ).group_by(Vulnerability.severity).all()

    sev_map = {s.lower(): c for s, c in sev_counts}

    dist_data = [
        {"name": "critical", "value": sev_map.get("critical", 0)},
        {"name": "high", "value": sev_map.get("high", 0) + sev_map.get("error", 0)},
        {"name": "medium", "value": sev_map.get("medium", 0) + sev_map.get("warning", 0)},
        {"name": "low", "value": sev_map.get("low", 0) + sev_map.get("note", 0)},
        {"name": "informational", "value": sev_map.get("informational", 0)}
    ]
    dist_data = [d for d in dist_data if d['value'] > 0]

    # B. Type Distribution (The Missing Piece)
    type_counts = session.query(
        Vulnerability.vulnerability_type,
        Vulnerability.severity,
        func.count(Vulnerability.id)
    ).filter(
        Vulnerability.report_id == latest_report.id
    ).group_by(
        Vulnerability.vulnerability_type, Vulnerability.severity
    ).all()

    type_map = {}
    for v_type, severity, count in type_counts:
        if v_type not in type_map:
            type_map[v_type] = {"name": v_type, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

        s_lower = severity.lower()
        if s_lower == 'error': s_lower = 'high'
        if s_lower == 'warning': s_lower = 'medium'
        if s_lower == 'note': s_lower = 'low'

        if s_lower in type_map[v_type]:
            type_map[v_type][s_lower] += count
        type_map[v_type]["total"] += count

    top_types = sorted(type_map.values(), key=lambda x: x['total'], reverse=True)[:5]

    return {
        "kpi": {
            "current_risk": latest_report.total_vulnerabilities,
            "stability_score": stability_score,
            "trend": trend_direction,
            "scan_date": latest_report.scan_date.strftime("%Y-%m-%d")
        },
        "charts": {
            "history": history_data,
            "distribution": dist_data,
            "types": top_types
        }
    }


def get_raw_vulnerabilities(
        session: Session,
        target_domain: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 1000
) -> list[dict]:
    """
    Fetches a raw list of vulnerabilities with filters.
    Limits to 1000 rows by default to prevent browser crashes on large datasets.
    """

    # Base Query: Vuln -> Report -> Scan (to get Target URL)
    # We use distinct() (no args) to deduplicate identical result rows caused by joins
    stmt = (
        select(
            Vulnerability.severity,
            Vulnerability.vulnerability_type,
            Vulnerability.endpoint,
            Vulnerability.scanner,
            Vulnerability.scan_date,
            Scan.target_url
        )
        .join(Report, Vulnerability.report_id == Report.id)
        .join(Scan, Report.id == Scan.report_id)
        .distinct() # Changed from .distinct(Vulnerability.id) to fix Sort Error
        .order_by(desc(Vulnerability.scan_date))
        .limit(limit)
    )

    # Apply Filters
    filters = []

    # Date Filter
    if start_date and end_date:
        try:
            s_date = datetime.strptime(start_date, "%Y-%m-%d")
            e_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            filters.append(Vulnerability.scan_date >= s_date)
            filters.append(Vulnerability.scan_date < e_date)
        except ValueError:
            pass

    # Target Filter
    if target_domain and target_domain != 'all':
        filters.append(Scan.target_url.ilike(f"%{target_domain}%"))

    if filters:
        stmt = stmt.where(and_(*filters))

    results = session.execute(stmt).all()

    # Format for Frontend
    data = []
    for row in results:
        data.append({
            "severity": row.severity,
            "type": row.vulnerability_type,
            "endpoint": row.endpoint,
            "scanner": row.scanner,
            "date": row.scan_date.strftime("%Y-%m-%d"),
            "target": row.target_url
        })

    return data