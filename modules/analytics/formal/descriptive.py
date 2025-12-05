from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session
import pandas as pd
import numpy as np

from modules.db.table_collection import Report, Scan, Vulnerability


def get_descriptive_stats(
        session: Session,
        mode: str = "snapshot",
        target_domain: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None
) -> Dict[str, Any]:
    """
    Calculates stats with support for Date Ranges and correct Contextual Logic.
    """

    # 1. Prepare Date Filters
    date_filters = []
    if start_date and end_date:
        try:
            s_date = datetime.strptime(start_date, "%Y-%m-%d")
            # Add 1 day to include the end date fully
            e_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            date_filters = [Scan.scan_date >= s_date, Scan.scan_date < e_date]
        except ValueError:
            pass  # Invalid date format, ignore filters

    # 2. Base Query Construction
    stmt = select(Report).join(Scan, Report.id == Scan.report_id)

    if mode == "snapshot":
        # SNAPSHOT MODE:
        # We need the "Latest Scan" for EVERY target within the date range (Global Context).
        # This ensures IQR and Prevalence are calculated against the full landscape.

        # Subquery: Find the max date for each target (respecting filters)
        subq_query = select(
            Scan.target_url,
            func.max(Scan.scan_date).label("latest_date")
        ).group_by(Scan.target_url)

        if date_filters:
            subq_query = subq_query.where(and_(*date_filters))

        latest_scan_subq = subq_query.subquery()

        # Join main query to this subquery
        stmt = stmt.join(
            latest_scan_subq,
            and_(
                Scan.target_url == latest_scan_subq.c.target_url,
                Scan.scan_date == latest_scan_subq.c.latest_date
            )
        )

        # NOTE: We do NOT apply 'target_domain' filter here yet.
        # We fetch all targets to calculate global stats (Prevalence/IQR),
        # then filter for the specific target in the DataFrame step.

    else:
        # TIME-SERIES / HISTORICAL MODE:
        # We just want all records matching criteria.

        # Apply Date Filters
        if date_filters:
            stmt = stmt.where(and_(*date_filters))

        # Apply Target Filter (Strict filtering for time-series)
        if target_domain and target_domain != 'all':
            stmt = stmt.where(Scan.target_url.ilike(f"%{target_domain}%"))

    # Execute Query
    reports = session.scalars(stmt).unique().all()

    if not reports:
        return {"meta": {"count": 0}, "message": "No reports found for this selection."}

    # 3. Process Data into DataFrames
    report_data = []

    for r in reports:
        if r.scan and len(r.scan) > 0:
            report_data.append({
                "report_id": r.id,
                "target": r.scan[0].target_url,
                "total_vulns": r.total_vulnerabilities
            })

    df_reports = pd.DataFrame(report_data)  # This is the "Context" (Global for snapshot)

    if df_reports.empty:
        return {"meta": {"count": 0}, "message": "No scan data found."}

    # 4. Handle Focus Filtering (The "Selected Target" Logic)
    df_focus = df_reports.copy()

    # If in SNAPSHOT mode and a target is selected, we create a 'focus' subset
    # but keep 'df_reports' as the global set.
    if mode == "snapshot" and target_domain and target_domain != 'all':
        df_focus = df_reports[df_reports['target'].str.contains(target_domain, case=False, na=False)]
        if df_focus.empty:
            # If the selected target isn't in the snapshot (e.g. date range excluded it), return empty
            return {"meta": {"count": 0}, "message": f"No data found for {target_domain} in this range."}

    # Get IDs for fetching vulnerabilities
    focus_report_ids = df_focus['report_id'].tolist()  # For Severity Charts
    global_report_ids = df_reports['report_id'].tolist()  # For Prevalence

    # 5. Fetch Vulnerabilities (Global Set)
    vuln_data_global = []
    if global_report_ids:
        # Fetch in bulk
        vuln_stmt = select(Vulnerability).where(Vulnerability.report_id.in_(global_report_ids))
        vulnerabilities = session.scalars(vuln_stmt).all()
        vuln_data_global = [{
            "severity": v.severity.capitalize(),
            "type": v.vulnerability_type,
            "report_id": v.report_id
        } for v in vulnerabilities]

    df_vulns_global = pd.DataFrame(vuln_data_global)

    # Create Focus Subset (For Charts)
    if not df_vulns_global.empty:
        df_vulns_focus = df_vulns_global[df_vulns_global['report_id'].isin(focus_report_ids)]
    else:
        df_vulns_focus = pd.DataFrame()

    # 6. Calculate Statistics
    stats = {
        "meta": {
            "mode": mode,
            "filter": target_domain or "all_targets",
            "report_count": len(df_focus),
            "total_findings": len(df_vulns_focus)
        },
        "findings_per_scan": {},
        "severity_distribution": {},
        "severity_type_distribution": [],
        "prevalence": {},
        "selected_target": None
    }

    # A. IQR Stats (Using GLOBAL Context)
    # This ensures that even when viewing one target, you see the "Industry Spread"
    if not df_reports.empty:
        mean_val = float(df_reports["total_vulns"].mean())
        std_dev = float(df_reports["total_vulns"].std()) if len(df_reports) > 1 else 0.0
        q1 = float(df_reports["total_vulns"].quantile(0.25))
        q3 = float(df_reports["total_vulns"].quantile(0.75))

        stats["findings_per_scan"] = {
            "mean": round(mean_val, 2),
            "median": float(df_reports["total_vulns"].median()),
            "std_dev": round(std_dev, 2),
            "q1": round(q1, 2),
            "q3": round(q3, 2),
            "iqr": round(q3 - q1, 2),
            "min": int(df_reports["total_vulns"].min()),
            "max": int(df_reports["total_vulns"].max()),
            "coefficient_of_variation": round((std_dev / mean_val) if mean_val > 0 else 0, 4)
        }

    # B. Vulnerability Analysis (Using FOCUS Data)
    # These charts should reflect the USER SELECTION (Specific Target)
    if not df_vulns_focus.empty:
        # 1. Severity Distribution
        stats["severity_distribution"] = df_vulns_focus["severity"].value_counts().to_dict()

        # 2. Severity by Type (Stacked)
        top_types = df_vulns_focus["type"].value_counts().head(10).index.tolist()
        subset = df_vulns_focus[df_vulns_focus["type"].isin(top_types)]

        stacked_data = []
        for v_type in top_types:
            type_rows = subset[subset["type"] == v_type]
            counts = type_rows["severity"].value_counts().to_dict()
            entry = {
                "type": v_type,
                "Critical": counts.get("Critical", 0),
                "High": counts.get("High", 0),
                "Medium": counts.get("Medium", 0),
                "Low": counts.get("Low", 0),
                "Informational": counts.get("Informational", 0),
                "total": len(type_rows)
            }
            stacked_data.append(entry)
        stats["severity_type_distribution"] = stacked_data

    # C. Prevalence (Using GLOBAL Data)
    # Prevalence means "How common is this across ALL targets?"
    if not df_vulns_global.empty:
        total_targets = len(df_reports)
        if total_targets > 0:
            prevalence_series = df_vulns_global.groupby("type")["report_id"].nunique()
            top_prevalence = prevalence_series.sort_values(ascending=False).head(10)
            stats["prevalence"] = (top_prevalence / total_targets * 100).round(1).to_dict()

    # D. Target Specific Metadata
    if mode == "snapshot" and target_domain and target_domain != 'all':
        if not df_focus.empty:
            val = int(df_focus.iloc[0]['total_vulns'])
            # Rank against global set
            rank = df_reports['total_vulns'].rank(pct=True)[df_focus.index[0]] * 100
            stats["selected_target"] = {
                "total_vulns": val,
                "rank_percentile": int(rank)
            }

    return stats


# ... existing imports
# Add these if missing:
from sqlalchemy import desc


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