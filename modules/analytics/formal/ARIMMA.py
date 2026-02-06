import pprint
from datetime import timedelta, datetime

import pandas as pd
from sqlalchemy.orm import Session
from statsmodels.tsa.arima.model import ARIMA
from statsmodels.tsa.statespace.sarimax import SARIMAX
import warnings

from modules.db.database import Database
from modules.db.table_collection import Report, Scan, Vulnerability

warnings.filterwarnings('ignore')


def arima_vulnerability_forecast(target_url: str, forecast_days: int = 30):
    """
    Simple ARIMA forecast for vulnerability trends
    """
    db = Database()
    engine = db.engine

    with Session(engine) as session:
        # Get historical data
        scans = session.query(
            Report.scan_date,
            Report.total_vulnerabilities
        ).join(Scan, Report.id == Scan.report_id).filter(
            Scan.target_url.contains(target_url),
        ).order_by(Report.scan_date).all()

        if len(scans) < 10:
            return {
                "error": "Need at least 10 scans for forecasting",
                "current_scans": len(scans)
            }

        # Create time series
        df = pd.DataFrame(scans, columns=['date', 'count'])
        df['date'] = pd.to_datetime(df['date'])
        df.set_index('date', inplace=True)
        df = df.sort_index()

        # Simple ARIMA model with fixed parameters
        model = ARIMA(df['count'], order=(1, 1, 1))
        fitted_model = model.fit()

        # Generate forecast
        forecast = fitted_model.forecast(steps=forecast_days)

        # Create forecast dates
        last_date = df.index[-1]
        forecast_dates = pd.date_range(
            start=last_date + timedelta(days=1),
            periods=forecast_days,
            freq='D'
        )

        # Build predictions
        predictions = []
        for date, pred in zip(forecast_dates, forecast):
            predictions.append({
                "date": date.strftime("%Y-%m-%d"),
                "predicted_vulnerabilities": max(0, int(round(pred)))
            })

        # Calculate trend
        trend = "increasing" if forecast.iloc[-1] > forecast.iloc[0] else "decreasing"

        return {
            "target_url": target_url,
            "model": "ARIMA(1,1,1)",
            "forecast_days": forecast_days,
            "predictions": predictions,
            "trend": trend,
            "historical_average": float(df['count'].mean()),
            "predicted_average": float(forecast.mean())
        }

def sarima_vulnerability_forecast(target_url: str, forecast_days: int = 30):
    """
    SARIMA forecast for detecting seasonal vulnerability patterns
    (e.g., more vulns discovered after weekend deployments)
    """
    db = Database()
    engine = db.engine

    with Session(engine) as session:
        cutoff_date = datetime.now() - timedelta(days=30)  # Need more data for SARIMA

        scans = session.query(Report).join(
            Scan, Report.id == Scan.report_id
        ).filter(
            Scan.target_url.contains(target_url),
            Report.scan_date >= cutoff_date
        ).order_by(Report.scan_date).all()

        if len(scans) < 10:
            return {
                "error": "Need at least 20 scans for SARIMA forecasting",
                "current_scans": len(scans),
                "recommendation": "Use ARIMA instead for shorter time series"
            }

        # Build time series data
        timeseries_data = []
        for scan in scans:
            vulns = session.query(Vulnerability).filter(
                Vulnerability.report_id == scan.id
            ).all()

            severity_counts = {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0
            }

            for vuln in vulns:
                severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

            timeseries_data.append({
                "date": scan.scan_date,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "critical_count": scan.critical_count,
                "severity_breakdown": severity_counts,
                "scan_type": scan.scan_type
            })

        # Convert to pandas DataFrame with proper datetime index
        df = pd.DataFrame(timeseries_data)
        df['date'] = pd.to_datetime(df['date'])
        df = df.set_index('date').sort_index()

        # Resample to daily frequency, filling missing dates with forward fill
        df = df.resample('D').asfreq()
        df['total_vulnerabilities'] = df['total_vulnerabilities'].fillna(method='ffill').fillna(0)

        # Extract the numerical series for SARIMA
        y = df['total_vulnerabilities']

        try:
            # SARIMA(p,d,q)(P,D,Q,s) where s=7 for weekly seasonality
            # Using simpler parameters to avoid overfitting with limited data
            model = SARIMAX(
                y,
                order=(1, 1, 1),  # (p,d,q) - non-seasonal
                seasonal_order=(1, 1, 1, 7),  # (P,D,Q,s) - weekly seasonality
                enforce_stationarity=False,
                enforce_invertibility=False
            )

            fitted = model.fit(disp=False)

            # Generate forecast
            forecast = fitted.forecast(steps=forecast_days)

            # Get confidence intervals
            forecast_obj = fitted.get_forecast(steps=forecast_days)
            conf_int = forecast_obj.conf_int()

            # Build predictions
            predictions = []
            last_date = df.index[-1]
            forecast_dates = pd.date_range(
                start=last_date + timedelta(days=1),
                periods=forecast_days,
                freq='D'
            )

            for i, date in enumerate(forecast_dates):
                predictions.append({
                    "date": date.strftime("%Y-%m-%d"),
                    "predicted_vulnerabilities": max(0, int(round(forecast.iloc[i]))),
                    "lower_bound": max(0, int(round(conf_int.iloc[i, 0]))),
                    "upper_bound": max(0, int(round(conf_int.iloc[i, 1])))
                })

            # Detect seasonality
            trend = "increasing" if forecast.iloc[-1] > forecast.iloc[0] else "decreasing"

            # Calculate day-of-week vulnerability pattern
            df['day_of_week'] = df.index.dayofweek
            weekly_pattern = df.groupby('day_of_week')['total_vulnerabilities'].mean()

            day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            weekly_breakdown = {
                day_names[i]: float(weekly_pattern.get(i, 0))
                for i in range(7)
            }

            return {
                "target_url": target_url,
                "model": "SARIMA(1,1,1)(1,1,1,7)",
                "forecast_days": forecast_days,
                "predictions": predictions,
                "trend": trend,
                "historical_average": float(y.mean()),
                "predicted_average": float(forecast.mean()),
                "weekly_pattern": weekly_breakdown,
                "model_aic": float(fitted.aic),
                "model_bic": float(fitted.bic),
                "seasonality_detected": any(
                    abs(v - y.mean()) > y.std() * 0.5
                    for v in weekly_pattern.values
                )
            }

        except Exception as e:
            return {
                "error": f"SARIMA fitting failed: {str(e)}",
                "recommendation": "Try ARIMA instead or collect more data",
                "data_points": len(y)
            }