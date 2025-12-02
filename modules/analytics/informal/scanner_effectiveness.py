from datetime import datetime, timedelta

from sqlalchemy.orm.session import Session
from sqlalchemy import func, case

from modules.db.database import Database
from modules.db.table_collection import Vulnerability, Report


def get_scanner_effectiveness(days: int = 30):
    """Compare Wapiti vs ZAP detection effectiveness"""
    db = Database()
    engine = db.engine
    cutoff_date = datetime.now() - timedelta(days=days)

    with Session(engine) as session:
        # Get scanner statistics
        scanner_stats = session.query(
            Vulnerability.scanner,
            func.count(Vulnerability.id).label('total_detections'),
            func.count(func.distinct(Vulnerability.vulnerability_type)).label('unique_vuln_types'),
            func.avg(
                case(
                    (Vulnerability.severity == 'Critical', 4),
                    (Vulnerability.severity == 'High', 3),
                    (Vulnerability.severity == 'Medium', 2),
                    (Vulnerability.severity == 'Low', 1),
                    else_=0
                )
            ).label('avg_severity_score')
        ).filter(
            Vulnerability.scan_date >= cutoff_date
        ).group_by(Vulnerability.scanner).all()

        comparison = {}
        for scanner, total, unique_types, avg_severity in scanner_stats:
            # Get confidence distribution
            confidence_dist = session.query(
                Vulnerability.confidence,
                func.count(Vulnerability.id).label('count')
            ).filter(
                Vulnerability.scanner == scanner,
                Vulnerability.scan_date >= cutoff_date
            ).group_by(Vulnerability.confidence).all()

            comparison[scanner] = {
                "total_detections": total,
                "unique_vulnerability_types": unique_types,
                "average_severity_score": float(avg_severity) if avg_severity else 0,
                "confidence_distribution": {
                    conf: count for conf, count in confidence_dist
                }
            }

        # Calculate overlap (from scans that used both scanners)
        full_scans = session.query(Report).filter(
            Report.scanner == 'all',
            Report.scan_date >= cutoff_date
        ).all()

        overlap_count = 0
        total_full_scans = len(full_scans)

        for scan in full_scans:
            wapiti_vulns = session.query(Vulnerability.vulnerability_type).filter(
                Vulnerability.report_id == scan.id,
                Vulnerability.scanner == 'wapiti'
            ).all()

            zap_vulns = session.query(Vulnerability.vulnerability_type).filter(
                Vulnerability.report_id == scan.id,
                Vulnerability.scanner == 'zap'
            ).all()

            wapiti_types = set([v[0] for v in wapiti_vulns])
            zap_types = set([v[0] for v in zap_vulns])
            overlap_count += len(wapiti_types.intersection(zap_types))

        return {
            "period_days": days,
            "scanner_comparison": comparison,
            "overlap_metrics": {
                "full_scans_analyzed": total_full_scans,
                "average_overlap": overlap_count / total_full_scans if total_full_scans > 0 else 0
            },
            "recommendation": "wapiti" if comparison.get("wapiti", {}).get("total_detections", 0) >
                                          comparison.get("zap", {}).get("total_detections", 0) else "zap"
        }