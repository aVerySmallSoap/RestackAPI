import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import r2_score, mean_squared_error

from sqlalchemy.orm import Session
from sqlalchemy import func

from modules.db.database import Database
from modules.db.table_collection import Report, Scan, Vulnerability


def vulnerability_correlation_analysis(target_domain: str = None):
    """
    Find correlations between scan characteristics and vulnerability counts
    Optionally filter by target_domain
    """
    db = Database()
    engine = db.engine

    with Session(engine) as session:
        # Base Query
        query = session.query(
            Scan.scan_duration,
            Scan.crawl_depth,
            Report.total_vulnerabilities,
            Report.critical_count,
            Scan.scanner
        ).join(Report, Scan.report_id == Report.id)

        # Apply Filter
        if target_domain:
            query = query.filter(Scan.target_url.like(f'%{target_domain}%'))

        data = query.all()

        if not data:
            return {
                "correlation_matrix": {},
                "significant_correlations": [],
                "insights": ["Insufficient data for correlation analysis"]
            }

        df = pd.DataFrame(data, columns=[
            'scan_duration', 'crawl_depth', 'total_vulns',
            'critical_count', 'scanner'
        ])

        # If data is constant or insufficient rows, correlation cannot be calculated
        if len(df) < 2:
            return {
                "correlation_matrix": {},
                "significant_correlations": [],
                "insights": ["Not enough data points to calculate correlation"]
            }

        # Encode categorical
        df['scanner_encoded'] = df['scanner'].astype('category').cat.codes

        # Correlation matrix
        correlation_matrix = df[[
            'scan_duration', 'crawl_depth', 'total_vulns',
            'critical_count', 'scanner_encoded'
        ]].corr()

        # Handle NaN correlations (happens if standard deviation is 0)
        correlation_matrix = correlation_matrix.fillna(0)

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
    seen_pairs = set()

    for corr in correlations:
        # Create a sorted tuple to avoid duplicate reverse pairs (A-B and B-A)
        pair = tuple(sorted((corr['variable_1'], corr['variable_2'])))
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)

        if 'scan_duration' in pair and 'total_vulns' in pair:
            if corr['correlation'] > 0:
                insights.append("Longer scans tend to find more vulnerabilities")
            else:
                insights.append("Longer scans are not yielding more findings; consider optimizing scan speed")

        elif 'crawl_depth' in pair and 'total_vulns' in pair:
            if corr['correlation'] > 0:
                insights.append("Deeper crawl depths are effectively uncovering more issues")

    if not insights:
        insights.append("No strong actionable patterns detected yet")

    return insights


# LINEAR REGRESSION

def regression_vulnerability_prediction(target_domain: str = None):
    """
    Use regression to predict vulnerability count based on scan features
    Optionally filter by target_domain
    """
    db = Database()
    engine = db.engine

    with Session(engine) as session:
        query = session.query(
            Scan.scan_duration,
            Scan.crawl_depth,
            func.count(Vulnerability.id).label('vuln_count')
        ).join(Report, Scan.report_id == Report.id
               ).outerjoin(Vulnerability, Report.id == Vulnerability.report_id)

        # Apply Filter
        if target_domain:
            query = query.filter(Scan.target_url.like(f'%{target_domain}%'))

        data = query.group_by(Scan.id, Scan.scan_duration, Scan.crawl_depth).all()

        if len(data) < 5:
            return {
                "error": "Insufficient data",
                "message": "Need at least 5 scans to train prediction model"
            }

        df = pd.DataFrame(data, columns=['scan_duration', 'crawl_depth', 'vuln_count'])

        # Features and target
        X = df[['scan_duration', 'crawl_depth']]
        y = df['vuln_count']

        # Split data
        # Ensure we have enough data for a split, otherwise just train on all
        if len(df) > 5:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
        else:
            X_train, y_train = X, y
            X_test, y_test = X, y

        # Train model
        model = LinearRegression()
        model.fit(X_train, y_train)

        # Predictions
        y_pred = model.predict(X_test)

        # Handle R2 score for small datasets where R2 might be negative or undefined
        try:
            r2 = float(r2_score(y_test, y_pred))
            rmse = float(np.sqrt(mean_squared_error(y_test, y_pred)))
        except:
            r2 = 0.0
            rmse = 0.0

        return {
            "model_type": "Linear Regression",
            "coefficients": {
                "scan_duration": float(model.coef_[0]),
                "crawl_depth": float(model.coef_[1]),
                "intercept": float(model.intercept_)
            },
            "predicted_next_month_vulns": float(np.mean(y_pred)),  # Simplified projection
            "trend_direction": "increasing" if model.coef_[0] > 0 else "decreasing",
            "model_accuracy": max(0, r2),  # R2 can be negative, clamp to 0 for UI
            "performance": {
                "r2_score": r2,
                "rmse": rmse
            },
            "interpretation": f"Each additional second of scanning predicts {model.coef_[0]:.2f} more vulnerabilities"
        }