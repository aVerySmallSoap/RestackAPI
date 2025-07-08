from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from modules.db.database import Database
from modules.filters.filter_date import date_filter_range
from modules.managers.report_manager import ReportManager
from modules.parsers.history_parser import history_parse, fetch_report, fetch_reports
from modules.parsers.wapiti_parser import parse as wapiti_parse, parse
from modules.scanners.wapiti_scan import scan as scan_wapiti

_report_manager = ReportManager()
_db = Database()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], #TODO: Fetch security certs and allow only a single origin
    allow_methods=["*"],
)

class URL(BaseModel):
    url:str

@app.post("/api/v1/wapiti/scan")
async def wapiti_scan(url: URL):
    print(url)
    _scan_start = datetime.now()
    _report_manager.generate(_scan_start.strftime("%Y%m%d_%I-%M-%S"))
    path = _report_manager.build()
    scan_wapiti(url.url, path)
    parsed = wapiti_parse(path)
    _db.insert_wapiti_report(_scan_start, path)
    return parsed

@app.get("/api/v1/wapiti/report/{report_id}")
async def wapiti_report(report_id: str):
    return parse(fetch_reports(report_id))

@app.get("/api/v1/whatweb/scan")
async def whatweb_scan(url: str):
    pass

@app.get("/api/v1/history/fetch")
async def history_fetch():
    return history_parse()

@app.get("/api/v1/report/{report_id}")
async def report_fetch(report_id: str):
    return fetch_report(report_id)

@app.get("/api/v1/filter/reports/range/")
async def filter_date_by_range(start:str, end:str):
    return date_filter_range(_db.engine, start, end)

if __name__ == '__main__':
    pass