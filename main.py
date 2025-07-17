from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from modules.db.database import Database
from modules.filters.filter_by_date import date_filter_range
from modules.managers.report_manager import ReportManager
from modules.parsers.history_parser import history_parse, fetch_report, fetch_reports
from modules.parsers.wapiti_parser import parse as wapiti_parse, parse
from modules.scanners.wapiti_scan import scan as scan_wapiti
from modules.utils.launch_tech_discovery import fetch_plugins_data, discover_then_volume, parse_volume_data

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

# TODO: Check if reports folder is present in CWD

@app.post("/api/v1/wapiti/scan")
async def wapiti_scan(url: URL):
    _URL = url.url
    _scan_start = datetime.now()
    _report_manager.generate(_scan_start.strftime("%Y%m%d_%I-%M-%S"))
    path = _report_manager.build()
    scan_wapiti(_URL, path)
    parsed = wapiti_parse(path)
    await discover_then_volume(_URL)
    raw_plugins = fetch_plugins_data()
    plugins = parse_volume_data()
    _db.insert_wapiti_quick_report(_scan_start, path, raw_plugins)
    return {"data": parsed, "plugins": plugins}

@app.get("/api/v1/whatweb/scan")
async def whatweb_scan(url: str):
    pass

@app.get("/api/v1/wapiti/report/{report_id}")
async def wapiti_report(report_id: str):
    return parse(fetch_reports(report_id))

@app.get("/api/v1/history/fetch")
async def history_fetch():
    return history_parse()

@app.get("/api/v1/report/{report_id}")
async def report_fetch(report_id: str):
    return fetch_report(report_id)

@app.get("/api/v1/filter/reports/range/")
async def filter_date_by_range(start:str, end:str):
    return date_filter_range(_db.engine, start, end)

@app.get("/api/v1/filter/reports/week/")
async def filter_date_by_month(date:str):
    pass

@app.get("/api/v1/filter/reports/month/")
async def filter_date_by_month(month:int):
    pass

@app.get("/api/v1/filter/reports/year/")
async def filter_date_by_year(year:int):
    pass

if __name__ == '__main__':
    pass