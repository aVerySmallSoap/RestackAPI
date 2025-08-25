import time
from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, AnyUrl

from modules.db.database import Database
from modules.db.filters.filter_by_date import date_filter_range
from modules.interfaces.enums.ScannerTypes import ScannerTypes
from modules.scanners.WapitiScanner import WapitiAdapter
from modules.scanners.WhatWebAdapter import WhatWebAdapter
from modules.scanners.ZapScanner import ZapAdapter
from services.ScannerEngine import ScannerEngine
from modules.parsers.history_parser import history_parse
from modules.utils.docker_utils import start_manual_zap_service
from modules.interfaces.enums.ZAPScanTypes import ZAPScanTypes

# == TEST WEBSITES ==
# https://public-firing-range.appspot.com
# https://github.com/WebGoat/WebGoat
# https://github.com/juice-shop/juice-shop
# ===================

_db = Database()
start_manual_zap_service({"apikey": "test"})
_scannerEngine = ScannerEngine()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], #TODO: Fetch security certs and allow only a single origin
    allow_methods=["*"],
)

class ScanRequest(BaseModel):
    url:AnyUrl

# TODO: Check if reports folder is present in CWD
# NOTE! THIS SHOULD BE DEVELOPED WITH SPECIALIZATION IN MIND. THIS APP SHOULD NOT BE GENERALIZED TO SPEED UP DEVELOPMENT
# CONSIDERATIONS ARE TO LIMIT SCANS TO ORGANIZATION SPECIFIC WEBSITES SUCH AS http://www.mywebsite.com or https://my.personal.site

@app.post("/api/v1/wapiti/scan")
async def wapiti_scan(request: ScanRequest) -> dict:
    time_start = time.perf_counter()
    _wapiti_scanner = WapitiAdapter()
    _whatweb_scanner = WhatWebAdapter()
    _URL = str(request.url)
    # == testing code ==
    isLocal = False
    local_url = ""
    if _URL.__contains__("localhost") or _URL.__contains__("127.0.0.1"):
        isLocal = True
        local_url = _URL.replace("localhost", "host.docker.internal")
    # == testing end ==
    _scan_start = datetime.now()
    _scannerEngine.enqueue_session(ScannerTypes.WAPITI, _scan_start)
    path = _scannerEngine.generate_path(ScannerTypes.WAPITI)
    config = _wapiti_scanner.generate_config({"path": path, "modules": ["all"]})
    _wapiti_scanner.start_scan(_URL, config)
    report = _wapiti_scanner.parse_results(path)
    if isLocal:
        await _whatweb_scanner.start_scan(local_url)
    else:
        await _whatweb_scanner.start_scan(_URL)
    _whatweb_results = _whatweb_scanner.parse_results()
    time_end = time.perf_counter()
    scan_time = time_end - time_start
    _db.insert_wapiti_quick_report(_scan_start, path, _whatweb_results["raw"], report, scan_time)
    return {"data": report["parsed"], "extra": report["extra"], "plugins": _whatweb_results["parsed"], "scan_time": scan_time}

@app.post("/api/v1/scan/zap/passive")
async def zap_passive_scan(request: ScanRequest) -> dict:
    time_start = time.perf_counter()
    _zap_scanner = ZapAdapter({"apikey": "test"})
    _whatweb_scanner = WhatWebAdapter()
    _URL = str(request.url)
    # == testing code ==
    isLocal = False
    local_url = ""
    if _URL.__contains__("localhost") or _URL.__contains__("127.0.0.1"):
        isLocal = True
        local_url = _URL.replace("localhost", "host.docker.internal")
    # == testing end ==
    _scan_start = datetime.now()
    _scannerEngine.enqueue_session(ScannerTypes.ZAP, _scan_start)
    path = _scannerEngine.generate_path(ScannerTypes.ZAP)
    if isLocal:
        await _whatweb_scanner.start_scan(local_url)
        _zap_scanner.start_scan(local_url, {"path": path, "scan_type": ZAPScanTypes.PASSIVE})
    else:
        await _whatweb_scanner.start_scan(_URL)
        _zap_scanner.start_scan(_URL, {"path": path})
    _whatweb_results = _whatweb_scanner.parse_results()
    report = _zap_scanner.parse_results(path)
    time_end = time.perf_counter()
    scan_time = time_end - time_start
    _db.insert_zap_report(_scan_start, path, _whatweb_results["raw"], report, scan_time)
    return {"data": report["parsed"], "plugins": _whatweb_results["parsed"], "scan_time": scan_time}

@app.get("/api/v1/wapiti/report/{report_id}")
async def wapiti_report(report_id: str) -> dict:
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