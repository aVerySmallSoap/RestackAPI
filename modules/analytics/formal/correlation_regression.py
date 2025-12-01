import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import r2_score, mean_squared_error

from sqlalchemy.orm import Session
from sqlalchemy import func

from modules.db.database import Database
from modules.db.table_collection import Report, Scan, Vulnerability


def vulnerability_correlation_analysis():
    """
    Find correlations between scan characteristics and vulnerability counts
    """
    db = Database()
    engine = db.engine

    with Session(engine) as session:
        # Get scan data
        data = session.query(
            Scan.scan_duration,
            Scan.crawl_depth,
            Report.total_vulnerabilities,
            Report.critical_count,
            Scan.scanner
        ).join(Report, Scan.report_id == Report.id).all()

        df = pd.DataFrame(data, columns=[
            'scan_duration', 'crawl_depth', 'total_vulns',
            'critical_count', 'scanner'
        ])

        # Encode categorical
        df['scanner_encoded'] = df['scanner'].astype('category').cat.codes

        # Correlation matrix
        correlation_matrix = df[[
            'scan_duration', 'crawl_depth', 'total_vulns',
            'critical_count', 'scanner_encoded'
        ]].corr()

        # Find significant correlations
        significant_correlations = []
        for col1 in correlation_matrix.columns:
            for col2 in correlation_matrix.columns:
                if col1 != col2:
                    corr_value = correlation_matrix.loc[col1, col2]
                    if abs(corr_value) > 0.5:  # Strong correlation
                        significant_correlations.append({
                            "variable_1": col1,
                            "variable_2": col2,
                            "correlation": float(corr_value),
                            "strength": "strong" if abs(corr_value) > 0.7 else "moderate"
                        })

        return {
            "correlation_matrix": correlation_matrix.to_dict(),
            "significant_correlations": significant_correlations,
            "insights": generate_correlation_insights(significant_correlations)
        }


def generate_correlation_insights(correlations):
    """Generate actionable insights"""
    insights = []
    for corr in correlations:
        if 'scan_duration' in corr['variable_1'] and 'total_vulns' in corr['variable_2']:
            if corr['correlation'] > 0:
                insights.append("Longer scans tend to find more vulnerabilities")
            else:
                insights.append("Scan duration doesn't correlate with vulnerability count")
    return insights

# LINEAR REGRESSION

def regression_vulnerability_prediction():
    """
    Use regression to predict vulnerability count based on scan features
    """
    db = Database()
    engine = db.engine

    with Session(engine) as session:
        data = session.query(
            Scan.scan_duration,
            Scan.crawl_depth,
            func.count(Vulnerability.id).label('vuln_count')
        ).join(Report, Scan.report_id == Report.id
               ).outerjoin(Vulnerability, Report.id == Vulnerability.report_id
                           ).group_by(Scan.id, Scan.scan_duration, Scan.crawl_depth).all()

        df = pd.DataFrame(data, columns=['scan_duration', 'crawl_depth', 'vuln_count'])

        # Features and target
        X = df[['scan_duration', 'crawl_depth']]
        y = df['vuln_count']

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )

        # Train model
        model = LinearRegression()
        model.fit(X_train, y_train)

        # Predictions
        y_pred = model.predict(X_test)

        return {
            "model_type": "Linear Regression",
            "coefficients": {
                "scan_duration": float(model.coef_[0]),
                "crawl_depth": float(model.coef_[1]),
                "intercept": float(model.intercept_)
            },
            "performance": {
                "r2_score": float(r2_score(y_test, y_pred)),
                "rmse": float(np.sqrt(mean_squared_error(y_test, y_pred)))
            },
            "interpretation": f"Each additional second of scanning predicts {model.coef_[0]:.2f} more vulnerabilities"
        }