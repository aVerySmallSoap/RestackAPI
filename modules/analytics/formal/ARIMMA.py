import pprint
from datetime import timedelta

import pandas as pd
from sqlalchemy.orm import Session
from statsmodels.tsa.arima.model import ARIMA
import warnings

from modules.db.database import Database
from modules.db.table_collection import Report, Scan

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
            Scan.target_url == target_url
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

pprint.pprint(arima_vulnerability_forecast('https://example.com/'))