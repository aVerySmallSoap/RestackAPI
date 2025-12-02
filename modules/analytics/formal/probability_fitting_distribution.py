from scipy import stats
import numpy as np
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from modules.db.database import Database
from modules.db.table_collection import Report, Scan


def vulnerability_distribution_analysis(report_id: str = None, target_domain: str = None):
    """
    Fit statistical distributions to vulnerability data
    Can filter by specific report_id OR target_domain (not both)
    """
    db = Database()
    engine = db.engine

    with Session(engine) as session:
        # Base query
        query = session.query(Report.total_vulnerabilities)

        # Apply filters
        if report_id:
            query = query.filter(Report.id == report_id)
        elif target_domain:
            query = query.join(
                Scan, Report.id == Scan.report_id
            ).filter(
                Scan.target_url.like(f'%{target_domain}%')
            )

        vuln_counts = [row[0] for row in query.all()]

        if not vuln_counts:
            return {
                "error": "No vulnerability data found for the specified filter",
                "filter": {
                    "report_id": report_id,
                    "target_domain": target_domain
                }
            }

        if len(vuln_counts) < 5:
            return {
                "error": "Insufficient data for distribution analysis (minimum 5 data points required)",
                "sample_size": len(vuln_counts),
                "data": vuln_counts
            }

        # Test multiple distributions
        distributions = {
            'normal': stats.norm,
            'poisson': stats.poisson,
            'exponential': stats.expon,
            'gamma': stats.gamma
        }

        results = {}
        for dist_name, distribution in distributions.items():
            try:
                # Fit distribution
                params = distribution.fit(vuln_counts)

                # Kolmogorov-Smirnov test (higher p-value = better fit)
                ks_stat, p_value = stats.kstest(vuln_counts, dist_name, args=params)

                results[dist_name] = {
                    "parameters": [float(p) for p in params],
                    "ks_statistic": float(ks_stat),
                    "p_value": float(p_value),
                    "goodness_of_fit": "good" if p_value > 0.05 else "poor"
                }
            except Exception as e:
                results[dist_name] = {
                    "error": f"Failed to fit {dist_name} distribution: {str(e)}"
                }

        # Descriptive statistics
        descriptive = {
            "mean": float(np.mean(vuln_counts)),
            "median": float(np.median(vuln_counts)),
            "std_dev": float(np.std(vuln_counts)),
            "variance": float(np.var(vuln_counts)),
            "skewness": float(stats.skew(vuln_counts)),
            "kurtosis": float(stats.kurtosis(vuln_counts)),
            "coefficient_of_variation": float(np.std(vuln_counts) / np.mean(vuln_counts)) if np.mean(
                vuln_counts) > 0 else 0,
            "min": int(min(vuln_counts)),
            "max": int(max(vuln_counts)),
            "sample_size": len(vuln_counts)
        }

        # Best fitting distribution (only from successful fits)
        valid_results = {k: v for k, v in results.items() if 'p_value' in v}

        if valid_results:
            best_fit = max(valid_results.items(), key=lambda x: x[1]['p_value'])
            best_fit_name = best_fit[0]
        else:
            best_fit_name = "none"

        result = {
            "descriptive_statistics": descriptive,
            "distribution_fits": results,
            "best_fit_distribution": best_fit_name,
            "interpretation": interpret_distribution(best_fit_name, descriptive)
        }

        # Add filter information
        if report_id:
            result["filtered_by"] = {"report_id": report_id}
        elif target_domain:
            result["filtered_by"] = {"target_domain": target_domain}

        return result


def interpret_distribution(dist_name, stats_dict):
    """Provide business interpretation"""
    if dist_name == 'poisson':
        return "Vulnerabilities occur at a constant average rate (random events)"
    elif dist_name == 'normal':
        return "Vulnerabilities cluster around average with symmetric spread"
    elif dist_name == 'exponential':
        return "Many scans have few vulnerabilities, fewer scans have many"
    elif dist_name == 'gamma':
        return "Vulnerabilities show right-skewed distribution with varying rates"
    elif dist_name == 'none':
        return "No standard distribution provides a good fit for this data"
    else:
        return f"Vulnerabilities follow a {dist_name} distribution"