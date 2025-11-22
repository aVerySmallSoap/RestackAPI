import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime

import aiofiles
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from loguru import logger
from pydantic import BaseModel, AnyUrl

from modules.analytics.vulnerability_analysis import analyze_results
from modules.db.database import Database
from modules.interfaces.enums.restack_enums import ZAPScanType, ScannerType
from modules.scanners.WapitiScanner import WapitiAdapter
from modules.scanners.WhatWebScanner import WhatWebAdapter
from modules.utils.__utils__ import check_directories, check_url_local_test, run_start_scan
from modules.utils.load_configs import DEV_ENV
from services.FileReportGenerator import generate_excel, generate_pdf
from services.managers.ScannerManager import ScannerManager
# == TESTING MODULES ==
from services.managers.ScheduleManager import ScheduleManager

# == END OF TESTING MODULES==

# == TEST WEBSITES ==
# https://github.com/WebGoat/WebGoat
# https://github.com/juice-shop/juice-shop
# https://github.com/OWASP-Benchmark/BenchmarkPython
# == END OF TESTING WEBSITES ==

# Initialize required modules and objects
_db = Database()
_schedule_manager = ScheduleManager(_db)
_scanner_manager = ScannerManager()
check_directories()
logger.add("./logs/{time}.log", rotation="10MB", enqueue=True)


@asynccontextmanager
async def lifespan(api: FastAPI):
    scheduler = _schedule_manager.initialize_apscheduler_jobs(_scanner_manager, _db)
    scheduler.start()
    api.state.scheduler = scheduler
    for schedule in scheduler.get_jobs():
        print(f"Name: {schedule.name}\ntrigger: {schedule.trigger}\n next run in: {schedule.next_run_time}\n")
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
    session = _scanner_manager.generate_unique_session()
    wapiti_config = _wapiti_scanner.generate_config(
        {
            "modules": ["all"]
        }
    )

    # scanning
    _URL = check_url_local_test(str(request.url))

    result = await asyncio.to_thread(
        run_start_scan,
        _scanner_manager,
        _URL,
        session,
        scanner_type=ScannerType.WAPITI,
        wapiti_config=wapiti_config,
        scanner_instance=_wapiti_scanner
    )

    # WhatWeb scan
    _whatweb_results, _query_results = await _whatweb_scanner.start_scan(_URL, session)

    time_end = time.perf_counter()
    scan_time = time_end - time_start

    if _whatweb_results.__contains__("error"):
        _db.insert_wapiti_quick_report(
            _scan_start,
            _whatweb_results["message"],
            result,
            scan_time,
            _URL
        )
        return {
            "data": result,
            "plugins": {
                "fingerprinted": _whatweb_results,
                "patchable": _query_results
            },
            "scan_time": scan_time
        }
    else:
        _db.insert_wapiti_quick_report(
            _scan_start,
            _whatweb_results["data"],
            result,
            scan_time,
            _URL
        )
        return {
            "data": result,
            "plugins": {
                "fingerprinted": _whatweb_results["data"],
                "patchable": _query_results
            },
            "scan_time": scan_time
        }


@app.post("/api/v1/wapiti/scan/full")
async def wapiti_scan_full(request: ScanRequest) -> dict:
    """Launches a wapiti scan with user-defined configurations"""
    raise HTTPException(status_code=500, detail="Not Yet Implemented")


@app.post("/api/v1/zap/scan/passive")
async def zap_passive_scan(request: ScanRequest) -> dict:
    """Starts a passive zap scan"""
    # Init
    time_start = time.perf_counter()
    _scan_start = datetime.now()
    session = _scanner_manager.generate_unique_session()
    _URL = check_url_local_test(str(request.url))
    zap_config = _scanner_manager.generate_random_config()

    zap_result, query_result, raw_whatweb_result = await asyncio.to_thread(
        run_start_scan,
        _scanner_manager,
        _URL,
        session,
        scanner_type=ScannerType.ZAP,
        scan_type=ZAPScanType.PASSIVE,
        api_key=zap_config["api_key"],
        port=zap_config["port"]
    )

    time_end = time.perf_counter()
    scan_time = time_end - time_start

    if query_result.__contains__("error"):
        _db.insert_zap_report(
            _scan_start,
            raw_whatweb_result,
            zap_result,
            scan_time,
            _URL
        )
        return {
            "data": zap_result,
            "plugins": {
                "fingerprinted": raw_whatweb_result,
                "patchable": query_result["message"]
            },
            "scan_time": scan_time
        }
    else:
        _db.insert_zap_report(
            _scan_start,
            raw_whatweb_result["data"],
            zap_result,
            scan_time,
            _URL
        )
        return {
            "data": zap_result,
            "plugins": {
                "fingerprinted": raw_whatweb_result,
                "patchable": query_result
            },
            "scan_time": scan_time
        }


@app.post("/api/v1/zap/scan/active")
async def zap_active_scan(request: ScanRequest) -> dict:
    """Starts an active zap scan"""
    # Init
    time_start = time.perf_counter()
    _scan_start = datetime.now()
    session = _scanner_manager.generate_unique_session()
    _URL = check_url_local_test(str(request.url))
    zap_config = _scanner_manager.generate_random_config()

    zap_result, query_result, raw_whatweb_result = await asyncio.to_thread(
        run_start_scan,
        _scanner_manager,
        _URL,
        session,
        scanner_type=ScannerType.ZAP,
        scan_type=ZAPScanType.ACTIVE,
        api_key=zap_config["api_key"],
        port=zap_config["port"]
    )

    time_end = time.perf_counter()
    scan_time = time_end - time_start

    if query_result.__contains__("error"):
        _db.insert_zap_report(
            _scan_start,
            raw_whatweb_result,
            zap_result,
            scan_time,
            _URL
        )
        return {
            "data": zap_result,
            "plugins": {
                "fingerprinted": raw_whatweb_result,
                "patchable": query_result["message"]
            },
            "scan_time": scan_time
        }
    else:
        _db.insert_zap_report(
            _scan_start,
            raw_whatweb_result["data"],
            zap_result,
            scan_time,
            _URL
        )
        return {
            "data": zap_result,
            "plugins": {
                "fingerprinted": raw_whatweb_result,
                "patchable": query_result
            },
            "scan_time": scan_time
        }


@app.post("/api/v1/zap/scan/full")
async def zap_full_scan(request: ScanRequest) -> dict:
    """Starts both a passive and active zap scan with user-defined configurations"""
    raise HTTPException(status_code=500, detail="Not Yet Implemented")


@app.post("/api/v1/scan/")
async def scan(request: ScanRequest) -> dict:
    """Starts multiple scans using all WAV tools (Wapiti and Zap) and fingerprinting tools (WhatWeb and SearchVulns) with pre-defined configurations"""
    # Init
    _wapiti_scanner = WapitiAdapter()
    full_scan_path = DEV_ENV["report_paths"]["full_scan"]

    time_start = time.perf_counter()
    _scan_start = datetime.now()
    _URL = check_url_local_test(str(request.url))
    session = _scanner_manager.generate_unique_session()
    zap_config = _scanner_manager.generate_random_config()
    wapiti_config = _wapiti_scanner.generate_config(
        {
            "modules": ["all"]
        }
    )

    zap_result, query_result, raw_whatweb_result = await asyncio.to_thread(
        run_start_scan,
        _scanner_manager,
        _URL,
        session,
        scanner_type=ScannerType.ZAP,
        scan_type=ZAPScanType.FULL,
        api_key=zap_config["api_key"],
        port=zap_config["port"]
    )

    wapiti_result = await asyncio.to_thread(
        run_start_scan,
        _scanner_manager,
        _URL,
        session,
        scanner_type=ScannerType.WAPITI,
        wapiti_config=wapiti_config,
        scanner_instance=_wapiti_scanner
    )

    # Analytics
    _results = analyze_results(session, wapiti_result, zap_result)

    time_end = time.perf_counter()
    scan_time = time_end - time_start

    # Save report in disk
    f = await aiofiles.open(f"{full_scan_path}\\{session}.json", "w")
    await f.write(json.dumps(
        {"data": _results, "plugins": {"fingerprinted": raw_whatweb_result, "patchable": query_result},
         "scan_time": scan_time}, indent=4))
    await f.close()

    # DB write
    if query_result.__contains__("error"):
        _db.insert_scan_report(
            _scan_start,
            raw_whatweb_result,
            zap_result,
            wapiti_result,
            _results,
            scan_time,
            _URL
        )
        return {
            "data": _results,
            "plugins": {
                "fingerprinted": raw_whatweb_result,
                "patchable": query_result["message"]
            },
            "scan_time": scan_time
        }
    else:
        _db.insert_scan_report(
            _scan_start,
            raw_whatweb_result["data"],
            zap_result,
            wapiti_result,
            _results,
            scan_time,
            _URL
        )
        return {
            "data": _results,
            "plugins": {
                "fingerprinted": raw_whatweb_result,
                "patchable": query_result
            },
            "scan_time": scan_time
        }


@app.post("/api/v1/scan/full")
async def scan_full(request: ScanRequest) -> dict:
    """Starts multiple scans using all WAV tools (Wapiti and Zap) and fingerprinting tools (WhatWeb and SearchVulns) with user-defined configurations"""
    raise HTTPException(status_code=500, detail="Not Yet Implemented")


@app.get("/api/v1/report/{report_id}/export/excel")
async def export_excel(report_id: str):
    """Generates and downloads the Excel report"""
    result = generate_excel(report_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])

    return FileResponse(
        result["path"],
        filename=os.path.basename(result["path"]),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


@app.get("/api/v1/report/{report_id}/export/pdf")
async def export_pdf(report_id: str):
    """Generates and downloads the PDF report"""
    result = generate_pdf(report_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])

    return FileResponse(
        result["path"],
        filename=os.path.basename(result["path"]),
        media_type="application/pdf"
    )
