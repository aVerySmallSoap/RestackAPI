from typing import Dict, Any, Optional
from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session
import pandas as pd
import numpy as np

from modules.db.table_collection import Report, Scan, Vulnerability


def get_descriptive_stats(session: Session, mode: str = "snapshot", target_domain: Optional[str] = None) -> Dict[
    str, Any]:
    """
    Calculates stats including the new 'Severity Type Distribution' (Stacked).
    """

    # 1. Base Query
    stmt = select(Report).join(Scan, Report.id == Scan.report_id)

    if mode == "snapshot":
        latest_scan_subq = (
            select(
                Scan.target_url,
                func.max(Scan.scan_date).label("latest_date")
            )
            .group_by(Scan.target_url)
            .subquery()
        )
        stmt = stmt.join(
            latest_scan_subq,
            and_(
                Scan.target_url == latest_scan_subq.c.target_url,
                Scan.scan_date == latest_scan_subq.c.latest_date
            )
        )
    elif target_domain and target_domain != 'all':
        stmt = stmt.where(Scan.target_url.ilike(f"%{target_domain}%"))

    reports = session.scalars(stmt).unique().all()

    if not reports:
        return {"meta": {"count": 0}, "message": "No reports found."}

    # 2. Data Processing
    report_data = []
    report_ids = []

    for r in reports:
        if r.scan and len(r.scan) > 0:
            report_data.append({
                "report_id": r.id,
                "target": r.scan[0].target_url,
                "total_vulns": r.total_vulnerabilities
            })
            report_ids.append(r.id)

    df_reports = pd.DataFrame(report_data)

    if df_reports.empty:
        return {"meta": {"count": 0}, "message": "No scan data found."}

    # Fetch granular vulnerabilities
    vuln_data = []
    if report_ids:
        vuln_stmt = select(Vulnerability).where(Vulnerability.report_id.in_(report_ids))
        vulnerabilities = session.scalars(vuln_stmt).all()
        vuln_data = [{
            "severity": v.severity.capitalize(),  # Normalize case
            "type": v.vulnerability_type,
            "report_id": v.report_id
        } for v in vulnerabilities]

    df_vulns = pd.DataFrame(vuln_data)

    # 3. Calculate Statistics
    stats = {
        "meta": {
            "mode": mode,
            "filter": target_domain or "all_targets",
            "report_count": len(df_reports),
            "total_findings": len(df_vulns)
        },
        "findings_per_scan": {},
        "severity_distribution": {},
        "severity_type_distribution": [],  # NEW: Stacked Data
        "prevalence": {}
    }

    # A. IQR Stats
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

    # B. Vulnerability Analysis
    if not df_vulns.empty:
        # 1. Simple Severity Dist
        stats["severity_distribution"] = df_vulns["severity"].value_counts().to_dict()

        # 2. NEW: Severity by Type (Stacked)
        # Get Top 10 types by total count
        top_types = df_vulns["type"].value_counts().head(10).index.tolist()

        # Filter for these types and group
        subset = df_vulns[df_vulns["type"].isin(top_types)]

        # Create a structured list for the frontend
        # Format: [{ type: "XSS", critical: 2, high: 5, medium: 10, low: 0 }, ...]
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

        # 3. Prevalence (Systemic Risk)
        total_targets = len(df_reports)
        if total_targets > 0:
            prevalence_series = df_vulns.groupby("type")["report_id"].nunique()
            top_prevalence = prevalence_series.sort_values(ascending=False).head(10)
            stats["prevalence"] = (top_prevalence / total_targets * 100).round(1).to_dict()

    # 4. Highlight Target
    if target_domain and target_domain != 'all':
        target_row = df_reports[df_reports['target'].str.contains(target_domain, case=False, na=False)]
        if not target_row.empty:
            val = int(target_row.iloc[0]['total_vulns'])
            rank = df_reports['total_vulns'].rank(pct=True)[target_row.index[0]] * 100
            stats["selected_target"] = {
                "total_vulns": val,
                "rank_percentile": int(rank)
            }

    return stats