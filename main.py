import json
import time
from contextlib import asynccontextmanager
from datetime import datetime

import aiofiles
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, AnyUrl

from modules.db.database import Database
from modules.interfaces.enums.ScanTypes import ScanType
from modules.interfaces.enums.ZAPScanTypes import ZAPScanTypes
from modules.interfaces.enums.ScannerTypes import ScannerTypes
from modules.scanners.WapitiScanner import WapitiAdapter
from modules.scanners.WhatWebScanner import WhatWebAdapter
from modules.scanners.ZapScanner import ZapAdapter
from modules.utils.load_configs import DEV_ENV
from services.ScannerEngine import ScannerEngine
from modules.utils.docker_utils import start_manual_zap_service, vuln_search_query, \
    parse_query, update_zap_service
from modules.utils.check_dir import check_directories
from modules.analytics.vulnerability_analysis import analyze_results

# == TESTING MODULES ==
from modules.utils.DEV_utils import check_url_local_test
from services.managers.ScheduleManager import ScheduleManager

# == END OF TESTING MODULES==

# == TEST WEBSITES ==
# https://github.com/WebGoat/WebGoat
# https://github.com/juice-shop/juice-shop
# https://github.com/OWASP-Benchmark/BenchmarkPython
# == END OF TESTING WEBSITES ==

_db = Database()
start_manual_zap_service({"apikey": "test"})
update_zap_service()
_scannerEngine = ScannerEngine()
_scheduleManager = ScheduleManager(_db)
check_directories()


@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler = _scheduleManager.initialize_apscheduler_jobs(_scannerEngine, _db)
    scheduler.start()
    yield
    if scheduler.running:
        scheduler.shutdown()

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
)

class ScanRequest(BaseModel):
    url: AnyUrl
    config: dict | None = None

@app.post("/api/v1/wapiti/scan/quick")
async def wapiti_scan(request: ScanRequest) -> dict:
    """Starts a configured wapiti scan"""
    time_start = time.perf_counter()
    # init
    _scan_start = datetime.now()
    _wapiti_scanner = WapitiAdapter()
    _whatweb_scanner = WhatWebAdapter()
    _scannerEngine.enqueue_session(ScannerTypes.WAPITI, _scan_start)
    session_name = _scannerEngine.dequeue_name()  # Get the latest time session and use it as the file name
    _wapiti_path = f"{DEV_ENV['report_paths']['wapiti']}\\{session_name}.json"
    _whatweb_path = f"{DEV_ENV['report_paths']['whatweb']}\\{session_name}.json"
    config = _wapiti_scanner.generate_config({"path": _wapiti_path, "modules": ["all"]})
    # scanning
    _URL = check_url_local_test(str(request.url))
    _wapiti_scanner.start_scan(_URL, ScanType.QUICK, config)
    _report = _wapiti_scanner.parse_results(_wapiti_path)
    # WhatWeb scan
    await _whatweb_scanner.start_scan(_URL, {"session_name": session_name})
    _whatweb_results = _whatweb_scanner.parse_results(_whatweb_path)
    # SearchVulns Query
    _query_results = {}
    if len(_whatweb_results["data"][0]) > 0 or _whatweb_results["data"][0] is not None:
        has_results = vuln_search_query(_whatweb_results["data"][0], session_name)
        if has_results:
            _query_results = parse_query(session_name)
        else:
            _query_results = None
    else:
        _query_results = None
    time_end = time.perf_counter()
    scan_time = time_end - time_start
    _db.insert_wapiti_quick_report(_scan_start, _wapiti_path, _whatweb_results["raw"], _report,
                                   scan_time)  # Rewrite reading of report variable
    if not _whatweb_results.__contains__("error"):
        return {"data": _report, "plugins": {"fingerprinted": _whatweb_results["data"], "patchable": _query_results},
                "scan_time": scan_time}
    else:
        return {"data": _report, "plugins": {"fingerprinted": _whatweb_results, "patchable": _query_results},
                "scan_time": scan_time}


@app.post("/api/v1/wapiti/scan/full")
async def wapiti_scan_full(request: ScanRequest) -> dict:
    """Launches a wapiti scan with user-defined configurations"""
    raise HTTPException(status_code=500, detail="Not Yet Implemented")


# TODO: Active and Passive scanning should be collapsed into a singular endpoint, the scan type should be defined in ScanRequest.config.scanType
@app.post("/api/v1/zap/scan/passive")
async def zap_passive_scan(request: ScanRequest) -> dict:
    """Starts a passive zap scan"""
    time_start = time.perf_counter()
    # init
    _scan_start = datetime.now()
    _zap_scanner = ZapAdapter({"apikey": "test"})
    _whatweb_scanner = WhatWebAdapter()
    _scannerEngine.enqueue_session(ScannerTypes.ZAP, _scan_start)
    session_name = _scannerEngine.dequeue_name()  # Get the latest time session and use it as the file name
    _zap_path = f"{DEV_ENV['report_paths']['zap']}\\{session_name}.json"
    _whatweb_path = f"{DEV_ENV['report_paths']['whatweb']}\\{session_name}.json"

    # scanning
    _URL = check_url_local_test(str(request.url))
    _zap_scanner.start_scan(_URL, {"path": _zap_path, "scan_type": ZAPScanTypes.PASSIVE, "apikey": "test"})
    _report = _zap_scanner.parse_results(_zap_path)

    # WhatWeb scan
    await _whatweb_scanner.start_scan(_URL, {"session_name": session_name})
    _whatweb_results = _whatweb_scanner.parse_results(_whatweb_path)
    # SearchVulns Query
    _query_results = {}
    if len(_whatweb_results["data"][0]) > 0 or _whatweb_results["data"][0] is not None:
        has_results = vuln_search_query(_whatweb_results["data"][0], session_name)
        if has_results:
            _query_results = parse_query(session_name)
        else:
            _query_results = None
    else:
        _query_results = None

    time_end = time.perf_counter()
    scan_time = time_end - time_start
    _db.insert_zap_report(_scan_start, _zap_path, _whatweb_results["data"], _report, scan_time, _URL)
    if not _whatweb_results.__contains__("error"):
        return {"data": _report, "plugins": {"fingerprinted": _whatweb_results["data"], "patchable": _query_results},
                "scan_time": scan_time}
    else:
        return {"data": _report, "plugins": {"fingerprinted": _whatweb_results, "patchable": _query_results},
                "scan_time": scan_time}


@app.post("/api/v1/zap/scan/active")
async def zap_active_scan(request: ScanRequest) -> dict:
    """Starts an active zap scan"""
    time_start = time.perf_counter()
    # init
    _scan_start = datetime.now()
    _zap_scanner = ZapAdapter({"apikey": "test"})
    _whatweb_scanner = WhatWebAdapter()
    _scannerEngine.enqueue_session(ScannerTypes.ZAP, _scan_start)
    session_name = _scannerEngine.dequeue_name()  # Get the latest time session and use it as the file name
    _zap_path = f"{DEV_ENV['report_paths']['zap']}\\{session_name}.json"
    _whatweb_path = f"{DEV_ENV['report_paths']['whatweb']}\\{session_name}.json"

    # scanning
    _URL = check_url_local_test(str(request.url))
    _zap_scanner.start_scan(_URL, {"path": _zap_path, "scan_type": ZAPScanTypes.ACTIVE, "apikey": "test"})
    _report = _zap_scanner.parse_results(_zap_path)

    # WhatWeb scan
    await _whatweb_scanner.start_scan(_URL, {"session_name": session_name})
    _whatweb_results = _whatweb_scanner.parse_results(_whatweb_path)
    # SearchVulns Query
    _query_results = {}
    if len(_whatweb_results["data"][0]) > 0 or _whatweb_results["data"][0] is not None:
        has_results = vuln_search_query(_whatweb_results["data"][0], session_name)
        if has_results:
            _query_results = parse_query(session_name)
        else:
            _query_results = None
    else:
        _query_results = None

    time_end = time.perf_counter()
    scan_time = time_end - time_start
    _db.insert_zap_report(_scan_start, _zap_path, _whatweb_results["data"], _report, scan_time, _URL)
    if not _whatweb_results.__contains__("error"):
        return {"data": _report, "plugins": {"fingerprinted": _whatweb_results["data"], "patchable": _query_results},
                "scan_time": scan_time}
    else:
        return {"data": _report, "plugins": {"fingerprinted": _whatweb_results, "patchable": _query_results},
                "scan_time": scan_time}


@app.post("/api/v1/zap/scan/full")
async def zap_full_scan(request: ScanRequest) -> dict:
    """Starts both a passive and active zap scan with user-defined configurations"""
    raise HTTPException(status_code=500, detail="Not Yet Implemented")


@app.post("/api/v1/scan/")
async def scan(request: ScanRequest) -> dict:
    """Starts multiple scans using all WAV tools (Wapiti and Zap) and fingerprinting tools (WhatWeb and SearchVulns) with pre-defined configurations"""
    time_start = time.perf_counter()
    # init
    _scan_start = datetime.now()
    _zap_scanner = ZapAdapter({"apikey": "test"})
    _wapiti_scanner = WapitiAdapter()
    _whatweb_scanner = WhatWebAdapter()
    _scannerEngine.enqueue_session(ScannerTypes.FULL, _scan_start)
    session_name = _scannerEngine.dequeue_name()  # Get the latest time session and use it as the file name
    _zap_path = f"{DEV_ENV['report_paths']['zap']}\\{session_name}.json"
    _wapiti_path = f"{DEV_ENV['report_paths']['wapiti']}\\{session_name}.json"
    _whatweb_path = f"{DEV_ENV['report_paths']['whatweb']}\\{session_name}.json"
    config = _wapiti_scanner.generate_config({"path": _wapiti_path, "modules": ["all"]})
    # scanning
    _URL = check_url_local_test(str(request.url))  # Check if the app is hosted locally

    # Zap scan
    _zap_scanner.start_scan(_URL, {"path": _zap_path, "scan_type": ZAPScanTypes.ACTIVE, "apikey": "test"})
    _zap_result = _zap_scanner.parse_results(_zap_path)
    # Wapiti scan
    _wapiti_scanner.start_scan(_URL, ScanType.QUICK, config)
    _wapiti_result = _wapiti_scanner.parse_results(_wapiti_path)

    # WhatWeb scan
    await _whatweb_scanner.start_scan(_URL, {"session_name": session_name})
    _whatweb_results = _whatweb_scanner.parse_results(_whatweb_path)

    # SearchVulns Query
    _query_results = {}
    if len(_whatweb_results["data"][0]) > 0 or _whatweb_results["data"][0] is not None:
        has_results = vuln_search_query(_whatweb_results["data"][0], session_name)
        if has_results:
            _query_results = parse_query(session_name)
        else:
            _query_results = None
    else:
        _query_results = None

    # Analytics
    _results = analyze_results(session_name, _wapiti_result, _zap_result)
    time_end = time.perf_counter()
    scan_time = time_end - time_start

    # Save report in disk
    f = await aiofiles.open(f"{DEV_ENV['report_paths']['full_scan']}\\{session_name}.json", "r")
    await f.write(json.dumps(
        {"data": _results, "plugins": {"fingerprinted": _whatweb_results["data"], "patchable": _query_results},
         "scan_time": scan_time}, indent=4))
    await f.close()
    # DB write
    _db.insert_scan_report(_scan_start, f"{DEV_ENV['report_paths']['full_scan']}\\{session_name}.json",
                           _whatweb_results["data"], _zap_result, _wapiti_result, _results, scan_time, _URL)
    if not _whatweb_results.__contains__("error"):
        return {"data": _results, "plugins": {"fingerprinted": _whatweb_results["data"], "patchable": _query_results},
                "scan_time": scan_time}
    else:
        return {"data": _results, "plugins": {"fingerprinted": _whatweb_results, "patchable": _query_results},
                "scan_time": scan_time}


@app.post("/api/v1/scan/full")
async def scan_full(request: ScanRequest) -> dict:
    """Starts multiple scans using all WAV tools (Wapiti and Zap) and fingerprinting tools (WhatWeb and SearchVulns) with user-defined configurations"""
    raise HTTPException(status_code=500, detail="Not Yet Implemented")
