import os

from modules.db.database import Database, Report
from sqlalchemy.orm import Session
from sqlalchemy import select
import json

db = Database()
engine = db.engine

def history_parse():
    with Session(engine) as session:
        _reports = []
        for row in session.execute(select(Report)):
            _temp = {}
            for obj in row:
                _temp.update({"id": obj.id})
                _temp.update({"date": obj.scan_date.strftime("%Y-%m-%d %H:%M:%S")})
                _temp.update({"scanner": obj.scanner})
                _temp.update({"type": obj.scan_type})
                # Fetch URL
                with open(obj.path, "r") as file:
                    report = json.load(file)
                    _temp.update({"target": report["infos"]["target"]})
            _reports.append(_temp)
    return _reports

def fetch_report(report_id):
    with Session(engine) as session:
        row = session.execute(select(Report).where(Report.id == report_id)).first()
        if row is None:
            return {"message": "report does not exist!"}
        _temp = {}
        for obj in row:
            _temp.update({"id": obj.id})
            _temp.update({"date": obj.scan_date.strftime("%Y-%m-%d %H:%M:%S")})
            _temp.update({"scanner": obj.scanner})
            _temp.update({"type": obj.scan_type})
            with open(obj.path, "r") as file:
                report = json.load(file)
                _temp.update({"target": report["infos"]["target"]})
        return _temp

def fetch_reports(report_id):
    with Session(engine) as session:
        for row in session.execute(select(Report).where(Report.id == report_id)).first():
            if row is None:
                return {"message": "report does not exist!"}
        return row.path