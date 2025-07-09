## This module contains the necessary functions to filter results by date
import json

import sqlalchemy
from sqlalchemy.orm import Session
from sqlalchemy import Engine, select

from modules.db.tables.Reports import Report


def date_filter_range(connection:Engine, start:str = None, end:str = None) -> list:
    """Filters results in a range of dates."""
    with Session(connection) as session:
        _reports = []
        for row in session.execute(select(Report).where(Report.scan_date >= start, Report.scan_date <= end)):
            _temp = {}
            for item in row:
                _temp.update({"id": item.id})
                _temp.update({"date": item.scan_date.strftime("%Y-%m-%d %H:%M:%S")})
                _temp.update({"scanner": item.scanner})
                _temp.update({"type": item.scan_type})
                # Fetch URL
                with open(item.path, "r") as file:
                    report = json.load(file)
                    _temp.update({"target": report["infos"]["target"]})
            _reports.append(_temp)
    return _reports

def date_filter_week(connection:Engine, date:str = None):
    """Filters results within a week."""
    pass

def date_filter_month(connection:Engine, month:int = None):
    """Filters results for the specified month."""
    with Session(connection) as session:
        _reports = []
        _results = session.execute(select(Report).filter(sqlalchemy.sql.extract('month', Report.scan_date)==month)).all()
        if len(_results) == 0:
            print("No results found")
            return None
        for row in _results:
            for item in row:
                print(f"{item.id}: {item.scan_date} | {item.scanner} |{item.scan_type}")
        return None


def date_filter_year(connection:Engine, year:str = None):
    """Filters results for the specified year."""
    with Session(connection) as session:
        _reports = []
        _results = session.execute(select(Report).filter(sqlalchemy.sql.extract('year', Report.scan_date)==year)).all()
        if len(_results) == 0:
            print("No results found")
            return None
        for row in _results:
            for item in row:
                print(f"{item.id}: {item.scan_date} | {item.scanner} |{item.scan_type}")
        return None

def date_filter(connection:Engine, date:str|int = None):
    """Filters results to a custom range of days"""
    pass