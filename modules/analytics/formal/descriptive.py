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
    Updated to aggregate vulnerabilities by date (one point per day).
    """

    # 1. DATE FILTER LOGIC
    if start_date and end_date:
        try:
            s_date = datetime.strptime(start_date, "%Y-%m-%d")
            e_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            cutoff_filter = and_(Report.scan_date >= s_date, Report.scan_date < e_date)
            days_analyzed = (datetime.strptime(end_date, "%Y-%m-%d") - s_date).days
        except ValueError:
            return {"error": "Invalid date format. Use YYYY-MM-DD"}
    else:
        # Default 30 Days
        days_analyzed = 30
        cutoff_date = datetime.now() - timedelta(days=30)
        cutoff_filter = Report.scan_date >= cutoff_date

    # 2. FETCH HISTORY WITH DAILY AGGREGATION
    # Group by date and sum vulnerabilities found that day
    stmt = (
        select(
            func.date(Report.scan_date).label('scan_date'),
            func.sum(Report.total_vulnerabilities).label('total_vulns'),
            func.sum(Report.critical_count).label('critical_vulns')
        )
        .join(Scan, Report.id == Scan.report_id)
        .where(cutoff_filter)
        .group_by(func.date(Report.scan_date))
        .order_by(func.date(Report.scan_date))
    )

    if target_domain and target_domain != 'all':
        stmt = stmt.where(Scan.target_url.ilike(f"%{target_domain}%"))

    # Execute aggregated query
    daily_results = session.execute(stmt).all()

    # Handle empty data gracefully
    if not daily_results:
        return {
            "kpi": {
                "target": target_domain if target_domain else "All Targets",
                "total_scans": 0,
                "total_vulns": 0,
                "days_analyzed": days_analyzed,
                "stability_score": 0,
                "last_scan": None
            },
            "charts": {
                "history": [],
                "distribution": [],
                "types": [],
                "trend": []
            }
        }

    # 3. PREPARE HISTORY DATA (aggregated by date)
    history_data = []
    for row in daily_results:
        history_data.append({
            "date": row.scan_date.strftime("%Y-%m-%d"),
            "timestamp": datetime.combine(row.scan_date, datetime.min.time()).timestamp(),
            "Total": int(row.total_vulns or 0),
            "Critical": int(row.critical_vulns or 0)
        })

    df = pd.DataFrame(history_data)

    # 4. GET ALL REPORTS IN TIME RANGE FOR ACCURATE COUNTS
    # Fetch all reports for the current filter to get accurate scan count and aggregated stats
    all_reports_stmt = (
        select(Report)
        .join(Scan, Report.id == Scan.report_id)
        .where(cutoff_filter)
    )

    if target_domain and target_domain != 'all':
        all_reports_stmt = all_reports_stmt.where(Scan.target_url.ilike(f"%{target_domain}%"))

    all_reports_stmt = all_reports_stmt.order_by(desc(Report.scan_date))
    all_reports = session.scalars(all_reports_stmt).all()

    # Get the latest report for "current state" reference
    latest_report = all_reports[0] if all_reports else None

    if not latest_report:
        return {
            "kpi": {
                "target": target_domain if target_domain else "All Targets",
                "total_scans": len(all_reports),
                "total_vulns": int(df['Total'].iloc[-1]) if len(df) > 0 else 0,
                "days_analyzed": days_analyzed,
                "stability_score": 0,
                "last_scan": df['date'].iloc[-1] if len(df) > 0 else None
            },
            "charts": {
                "history": history_data,
                "distribution": [],
                "types": [],
                "trend": []
            }
        }

    # 7. STATISTICAL ANALYSIS (Stability & Trend)
    total_scans = len(daily_results)
    stability_score = 0
    trend_data = []

    if len(df) > 1:
        # Stability (Coefficient of Variation)
        mean = df['Total'].mean()
        std = df['Total'].std()
        cov = std / mean if mean > 0 else 0
        stability_score = max(0, int(100 - (cov * 100)))

        # Regression Line Calculation
        x_vals = np.arange(len(df))
        y_vals = df['Total'].values

        slope, intercept = np.polyfit(x_vals, y_vals, 1)
        df['regression'] = (slope * x_vals) + intercept

        trend_df = df[['date', 'Total', 'regression']].rename(columns={'Total': 'value'})
        trend_data = trend_df.to_dict(orient='records')
    else:
        stability_score = 100
        trend_data = [{"date": r["date"], "value": r["Total"], "regression": r["Total"]} for r in history_data]

    # 6. SNAPSHOT ANALYSIS - AGGREGATED ACROSS ALL REPORTS IN TIME RANGE
    # Instead of just the latest report, aggregate ALL reports in the filtered time range

    # A. Severity Distribution (from ALL reports in range)
    all_report_ids = [r.id for r in all_reports]

    if not all_report_ids:
        dist_data = []
        top_types = []
    else:
        sev_counts = session.query(
            Vulnerability.severity, func.count(Vulnerability.id)
        ).filter(
            Vulnerability.report_id.in_(all_report_ids)
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

        # B. Type Distribution (Top 5 by Count across ALL reports)
        type_counts = session.query(
            Vulnerability.vulnerability_type,
            Vulnerability.severity,
            func.count(Vulnerability.id)
        ).filter(
            Vulnerability.report_id.in_(all_report_ids)
        ).group_by(
            Vulnerability.vulnerability_type, Vulnerability.severity
        ).all()

        type_map = {}
        for v_type, severity, count in type_counts:
            clean_type = v_type.replace('_', ' ').replace('-', ' ').title()

            if clean_type not in type_map:
                type_map[clean_type] = {"name": clean_type, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

            s_lower = severity.lower()
            if s_lower == 'error': s_lower = 'high'
            if s_lower == 'warning': s_lower = 'medium'
            if s_lower == 'note': s_lower = 'low'

            if s_lower in type_map[clean_type]:
                type_map[clean_type][s_lower] += count
            type_map[clean_type]["total"] += count

        top_types = sorted(type_map.values(), key=lambda x: x['total'], reverse=True)[:5]

    return {
        "kpi": {
            "target": target_domain if target_domain else "All Targets",
            "total_scans": total_scans,
            "total_vulns": latest_report.total_vulnerabilities,  # Current state from latest scan
            "total_vulns_all_time": sum(r.total_vulnerabilities for r in all_reports),  # Cumulative across all scans
            "days_analyzed": days_analyzed,
            "stability_score": stability_score,
            "last_scan": latest_report.scan_date.strftime("%Y-%m-%d")
        },
        "charts": {
            "history": history_data,
            "distribution": dist_data,
            "types": top_types,
            "trend": trend_data
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
    """
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
        .distinct()
        .order_by(desc(Vulnerability.scan_date))
        .limit(limit)
    )

    filters = []
    if start_date and end_date:
        try:
            s_date = datetime.strptime(start_date, "%Y-%m-%d")
            e_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            filters.append(Vulnerability.scan_date >= s_date)
            filters.append(Vulnerability.scan_date < e_date)
        except ValueError:
            pass

    if target_domain and target_domain != 'all':
        filters.append(Scan.target_url.ilike(f"%{target_domain}%"))

    if filters:
        stmt = stmt.where(and_(*filters))

    results = session.execute(stmt).all()

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