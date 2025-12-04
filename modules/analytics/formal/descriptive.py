from typing import Dict, Any, Optional
from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session
import pandas as pd

from modules.db.table_collection import Report, Scan, Vulnerability


def get_descriptive_stats(session: Session, mode: str = "snapshot", target_domain: Optional[str] = None) -> Dict[
    str, Any]:
    """
    Calculates descriptive stats including Prevalence and Hotspots.
    """
    # 1. Base Query
    stmt = select(Report).join(Scan, Report.id == Scan.report_id)

    # 2. Filter Logic
    if target_domain and target_domain != 'all':
        stmt = stmt.where(Scan.target_url.ilike(f"%{target_domain}%"))

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

    reports = session.scalars(stmt).unique().all()

    if not reports:
        return {"meta": {"count": 0}, "message": "No reports found."}

    # 3. Data Processing
    report_data = []
    report_ids = []

    for r in reports:
        if r.scan and len(r.scan) > 0:
            target_url = r.scan[0].target_url
            report_data.append({
                "report_id": r.id,
                "target": target_url,
                "total_vulns": r.total_vulnerabilities,
                "critical_count": r.critical_count
            })
            report_ids.append(r.id)

    df_reports = pd.DataFrame(report_data)

    if df_reports.empty:
        return {"meta": {"count": 0}, "message": "No valid scan data found."}

    # Fetch granular data (Now including vulnerability_type)
    vuln_data = []
    if report_ids:
        vuln_stmt = select(Vulnerability).where(Vulnerability.report_id.in_(report_ids))
        vulnerabilities = session.scalars(vuln_stmt).all()
        # Fetch 'type' for Prevalence analysis
        vuln_data = [{"severity": v.severity, "type": v.vulnerability_type, "report_id": v.report_id} for v in
                     vulnerabilities]

    df_vulns = pd.DataFrame(vuln_data)

    # 4. Calculate Statistics
    stats = {
        "meta": {
            "mode": mode,
            "filter": target_domain or "all_targets",
            "report_count": len(df_reports),
            "total_findings": len(df_vulns)
        },
        "prevalence": {},
        "hotspots": []
    }

    if not df_reports.empty:
        # Standard Stats
        mean_val = float(df_reports["total_vulns"].mean())
        std_dev = float(df_reports["total_vulns"].std()) if len(df_reports) > 1 else 0.0
        q1 = float(df_reports["total_vulns"].quantile(0.25))
        q3 = float(df_reports["total_vulns"].quantile(0.75))
        coef_var = (std_dev / mean_val) if mean_val > 0 else 0.0

        stats["findings_per_scan"] = {
            "mean": round(mean_val, 2),
            "median": float(df_reports["total_vulns"].median()),
            "std_dev": round(std_dev, 2),
            "q1": round(q1, 2),
            "q3": round(q3, 2),
            "iqr": round(q3 - q1, 2),
            "min": int(df_reports["total_vulns"].min()),
            "max": int(df_reports["total_vulns"].max()),
            "coefficient_of_variation": round(coef_var, 4)
        }

        # METRIC: Hotspots (Top Riskiest Assets)
        # Sort by critical count, then total vulns
        hotspots_df = df_reports.sort_values(by=['critical_count', 'total_vulns'], ascending=False).head(5)
        stats["hotspots"] = hotspots_df[['target', 'critical_count', 'total_vulns']].to_dict(orient='records')

    if not df_vulns.empty:
        df_vulns["severity"] = df_vulns["severity"].str.capitalize()
        severity_counts = df_vulns["severity"].value_counts().to_dict()
        total_findings = len(df_vulns)
        stats["severity_distribution"] = severity_counts
        stats["severity_ratios"] = {k: round(v / total_findings, 3) for k, v in severity_counts.items()}

        # METRIC: Prevalence (Systemic Risk)
        # Count unique report_ids per vulnerability type
        if "type" in df_vulns.columns:
            total_targets = len(df_reports)
            prevalence_df = df_vulns.groupby("type")["report_id"].nunique().sort_values(ascending=False).head(10)
            # Convert to percentage (0-100)
            stats["prevalence"] = (prevalence_df / total_targets * 100).round(1).to_dict()

    return stats