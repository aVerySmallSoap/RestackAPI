from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func
import statistics
from collections import Counter

from modules.db.database import Database
from modules.db.table_collection import Scan, Report, Vulnerability


def calculate_stats(data_list):
    """Helper to calculate descriptive statistics for a list of numbers"""
    if not data_list:
        return {
            "mean": 0, "median": 0, "mode": 0, "cv": 0,
            "q1": 0, "q3": 0, "iqr": 0, "min": 0, "max": 0
        }

    mean_val = statistics.mean(data_list)
    median_val = statistics.median(data_list)
    try:
        mode_val = statistics.mode(data_list)
    except:
        mode_val = median_val

    stdev_val = statistics.stdev(data_list) if len(data_list) > 1 else 0
    cv_val = (stdev_val / mean_val * 100) if mean_val != 0 else 0

    quantiles = statistics.quantiles(data_list, n=4) if len(data_list) >= 2 else [0, 0, 0]
    q1, q3 = quantiles[0], quantiles[2]
    iqr_val = q3 - q1

    return {
        "mean": round(mean_val, 2),
        "median": round(median_val, 2),
        "mode": round(mode_val, 2),
        "cv": round(cv_val, 2),  # Coefficient of Variation
        "q1": round(q1, 2),
        "q3": round(q3, 2),
        "iqr": round(iqr_val, 2),
        "min": min(data_list),
        "max": max(data_list)
    }


def get_descriptive_stats(target_domain: str = None):
    db = Database()

    with Session(db.engine) as session:
        # 1. Fetch Scans and related Report data
        query = session.query(Scan, Report).join(Report, Scan.report_id == Report.id)

        if target_domain:
            query = query.filter(Scan.target_url.like(f'%{target_domain}%'))

        results = query.order_by(Scan.scan_date).all()

        # 2. Extract Data Series
        scan_durations = []
        vuln_counts = []
        trend_dates = []
        trend_counts = []

        for scan, report in results:
            # Data for Box Plots and Stats
            duration = scan.scan_duration or 0
            count = report.total_vulnerabilities or 0

            scan_durations.append(duration)
            vuln_counts.append(count)

            # Data for Trend Line
            if scan.scan_date:
                date_str = scan.scan_date.strftime("%Y-%m-%d")
                trend_dates.append(date_str)
                trend_counts.append(count)

        # 3. Fetch Severity Distribution (for Histogram)
        vuln_query = session.query(Vulnerability.severity)
        if target_domain:
            vuln_query = vuln_query.join(Report, Vulnerability.report_id == Report.id) \
                .join(Scan, Report.id == Scan.report_id) \
                .filter(Scan.target_url.like(f'%{target_domain}%'))

        vuln_severities = [r[0] for r in vuln_query.all()]
        severity_counts = dict(Counter(vuln_severities))

        # 4. Construct Response
        return {
            "statistics": {
                "duration": calculate_stats(scan_durations),
                "vulnerabilities": calculate_stats(vuln_counts)
            },
            "charts": {
                "trend": {
                    "x": trend_dates,
                    "y": trend_counts
                },
                "distribution_severity": {
                    "x": list(severity_counts.keys()),
                    "y": list(severity_counts.values())
                },
                "box_plots": {
                    "duration": scan_durations,
                    "vulnerability_counts": vuln_counts
                }
            }
        }