import pprint

from scipy import stats
import numpy as np

from sqlalchemy.orm import Session

from modules.db.database import Database
from modules.db.table_collection import Report


def vulnerability_distribution_analysis(report_id: str = None):
    """
    Fit statistical distributions to vulnerability data
    """
    db = Database()
    engine = db.engine

    with Session(engine) as session:
        query = session.query(Report.total_vulnerabilities)
        if report_id:
            query = query.filter(Report.id == report_id)

        vuln_counts = [row[0] for row in query.all()]
        print(vuln_counts)

        # if len(vuln_counts) < 30:
        #     return {"error": "Insufficient data for distribution analysis"}

        # Test multiple distributions
        distributions = {
            'normal': stats.norm,
            'poisson': stats.poisson,
            'exponential': stats.expon,
            'gamma': stats.gamma
        }

        results = {}
        for dist_name, distribution in distributions.items():
            # Fit distribution
            params = distribution.fit(vuln_counts)

            # Kolmogorov-Smirnov test (lower p-value = worse fit)
            ks_stat, p_value = stats.kstest(vuln_counts, dist_name, args=params)

            results[dist_name] = {
                "parameters": params,
                "ks_statistic": ks_stat,
                "p_value": p_value,
                "goodness_of_fit": "good" if p_value > 0.05 else "poor"
            }

        # Descriptive statistics
        descriptive = {
            "mean": np.mean(vuln_counts),
            "median": np.median(vuln_counts),
            "std_dev": np.std(vuln_counts),
            "variance": np.var(vuln_counts),
            "skewness": stats.skew(vuln_counts),
            "kurtosis": stats.kurtosis(vuln_counts),
            "coefficient_of_variation": np.std(vuln_counts) / np.mean(vuln_counts)
        }

        # Best fitting distribution
        best_fit = max(results.items(), key=lambda x: x[1]['p_value'])

        return {
            "descriptive_statistics": descriptive,
            "distribution_fits": results,
            "best_fit_distribution": best_fit[0],
            "interpretation": interpret_distribution(best_fit[0], descriptive)
        }


def interpret_distribution(dist_name, stats):
    """Provide business interpretation"""
    if dist_name == 'poisson':
        return "Vulnerabilities occur at a constant average rate (random events)"
    elif dist_name == 'normal':
        return "Vulnerabilities cluster around average with symmetric spread"
    elif dist_name == 'exponential':
        return "Many scans have few vulnerabilities, fewer scans have many"
    else:
        return f"Vulnerabilities follow a {dist_name} distribution"

pprint.pprint(vulnerability_distribution_analysis("5763dc41-1c14-44d4-ad91-69c4e50d299e"))