from modules.db.database import Database, Report
from sqlalchemy.orm import Session
from sqlalchemy import select
import json

db = Database() # TODO: Remove this and just pass the global database set on main.py
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

