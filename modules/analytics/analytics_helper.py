"""
Helper to compute and store analytics during report insertion
"""
from modules.analytics.vulnerability_analysis import generate_summary_stats, create_priority_matrix
from modules.analytics.ai_recosum import summarize_with_ai
from loguru import logger


def compute_and_attach_analytics(report, analytics_data: dict, session_name: str):
    """
    Compute analytics from analysis data and attach to report object.
    Call this BEFORE session.commit() so all data is saved atomically.
    """
    try:
        # 1. Generate Summary Statistics
        stats = generate_summary_stats(analytics_data)
        report.high_confidence_vulns = stats.get("high_confidence_vulns", 0)
        report.medium_confidence_vulns = stats.get("medium_confidence_vulns", 0)
        report.low_confidence_vulns = stats.get("low_confidence_vulns", 0)

        agreement_str = stats.get("scanner_agreement_rate", "0%")
        confidence_str = stats.get("confidence_rate", "0%")

        report.scanner_agreement_rate = float(agreement_str.rstrip('%')) if agreement_str else 0.0
        report.confidence_rate = float(confidence_str.rstrip('%')) if confidence_str else 0.0

        # 2. Generate Priority Matrix
        matrix_data = create_priority_matrix(analytics_data)
        report.high_severity_high_confidence = matrix_data["quadrant_counts"]["high_severity_high_confidence"]
        report.high_severity_low_confidence = matrix_data["quadrant_counts"]["high_severity_low_confidence"]
        report.low_severity_high_confidence = matrix_data["quadrant_counts"]["low_severity_high_confidence"]
        report.low_severity_low_confidence = matrix_data["quadrant_counts"]["low_severity_low_confidence"]

        # 3. Generate AI Summary (if available)
        try:
            ai_summary = summarize_with_ai(session_name)
            if ai_summary and "summary" in ai_summary:
                report.ai_summary_vulnerabilities = ai_summary["summary"].get("vulnerabilities", "")
                report.ai_summary_tech = ai_summary["summary"].get("tech", "")
        except Exception as e:
            logger.warning(f"AI summary generation failed for {session_name}: {e}")
            report.ai_summary_vulnerabilities = None
            report.ai_summary_tech = None

        return report

    except Exception as e:
        logger.error(f"Error computing analytics: {e}")
        return report