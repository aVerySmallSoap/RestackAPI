import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime

import aiofiles
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from loguru import logger
from pydantic import BaseModel, AnyUrl

from modules.analytics.ai_recosum import summarize_with_ai
from modules.analytics.vulnerability_analysis import analyze_results, generate_summary_stats, create_priority_matrix
from modules.db.database import Database
from modules.interfaces.enums.restack_enums import ZAPScanType, ScannerType, ScanStep
from modules.scanners.WapitiScanner import WapitiAdapter
from modules.scanners.WhatWebScanner import WhatWebAdapter
from modules.utils.__utils__ import check_directories, check_url_local_test, run_start_scan
from modules.utils.load_configs import DEV_ENV
from services.FileReportGenerator import generate_excel, generate_pdf
from modules.utils.preinstances import scan_tracker
from services.managers.ScannerManager import ScannerManager
from services.managers.ConnectionManager import connection_manager
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
    scheduler = _schedule_manager.initialize_apscheduler_jobs(_scanner_manager, scan_tracker, _db)
    scheduler.start()
    api.state.scheduler = scheduler
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

class ScheduleRequest(BaseModel):
    name: str
    target: AnyUrl
    job_type: str
    interval: dict


@app.post("/api/v1/wapiti/scan/quick")
async def wapiti_scan(request: ScanRequest) -> dict:
    """Starts a configured wapiti scan"""
    time_start = time.perf_counter()
    # init
    _scan_start = datetime.now()
    _wapiti_scanner = WapitiAdapter()
    _whatweb_scanner = WhatWebAdapter()
    session = scan_tracker.generate_unique_session()
    _URL = check_url_local_test(str(request.url))
    wapiti_config = _wapiti_scanner.generate_config(
        {
            "modules": ["all"]
        }
    )
    scan_tracker.add_scan(session, _URL, ScanStep.INIT)

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
    scan_tracker.advance_step(session, ScanStep.CLEANUP)

    time_end = time.perf_counter()
    scan_time = time_end - time_start

    scan_tracker.advance_step(session, ScanStep.SAVING)
    if _whatweb_results.__contains__("error"):
        _db.insert_wapiti_quick_report(
            _scan_start,
            _whatweb_results["message"],
            result,
            scan_time,
            _URL
        )
        scan_tracker.advance_step(session, ScanStep.SUCCESS)
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
        scan_tracker.advance_step(session, ScanStep.SUCCESS)
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
    session = scan_tracker.generate_unique_session()
    _URL = check_url_local_test(str(request.url))
    zap_config = _scanner_manager.generate_random_config()
    scan_tracker.add_scan(session, _URL, ScanStep.INIT)

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

    scan_tracker.advance_step(session, ScanStep.SAVING)
    if query_result.__contains__("error"):
        _db.insert_zap_report(
            _scan_start,
            raw_whatweb_result,
            zap_result,
            scan_time,
            _URL
        )
        scan_tracker.advance_step(session, ScanStep.SUCCESS)
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
        scan_tracker.advance_step(session, ScanStep.SUCCESS)
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
    session = scan_tracker.generate_unique_session()
    _URL = check_url_local_test(str(request.url))
    zap_config = _scanner_manager.generate_random_config()
    scan_tracker.add_scan(session, _URL, ScanStep.INIT)

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

    scan_tracker.advance_step(session, ScanStep.SAVING)
    if query_result.__contains__("error"):
        _db.insert_zap_report(
            _scan_start,
            raw_whatweb_result,
            zap_result,
            scan_time,
            _URL
        )
        scan_tracker.advance_step(session, ScanStep.SUCCESS)
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
        scan_tracker.advance_step(session, ScanStep.SUCCESS)
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
    session = scan_tracker.generate_unique_session()
    zap_config = _scanner_manager.generate_random_config()
    wapiti_config = _wapiti_scanner.generate_config(
        {
            "modules": ["all"]
        }
    )
    scan_tracker.add_scan(session, _URL, ScanStep.INIT)

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

    time_end = time.perf_counter()
    scan_time = time_end - time_start

    # Analytics
    scan_tracker.advance_step(session, ScanStep.ANALYZING)
    _results = analyze_results(session, wapiti_result, zap_result)
    summary_stats = generate_summary_stats(_results)
    priority_matrix = create_priority_matrix(_results)
    ai_summary = summarize_with_ai(session)

    data = {
        "data": _results,
        "plugins": {
            "fingerprinted": raw_whatweb_result,
            "patchable": query_result
        },
        "scan_time": scan_time,
        "summary": {
                "stats": summary_stats,
                "matrix": priority_matrix,
                "ai": ai_summary
        }
    }
    with open(f"{DEV_ENV['report_paths']['full_scan']}\\{session}.json", "w+") as writable:
        writable.write(json.dumps(data))
        writable.flush()
        writable.close()



    # Save report in disk
    scan_tracker.advance_step(session, ScanStep.SAVING)
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
        scan_tracker.advance_step(session, ScanStep.SUCCESS)
        return {
            "data": _results,
            "summary": {
                "stats": summary_stats,
                "matrix": priority_matrix,
                "ai": ai_summary
            },
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
        scan_tracker.advance_step(session, ScanStep.SUCCESS)
        return {
            "data": _results,
            "summary": {
                "stats": summary_stats,
                "matrix": priority_matrix,
                "ai": ai_summary
            },
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

@app.post("/api/v1/schedule/add/")
async def add_schedule(job: ScheduleRequest):
    pass

@app.websocket("/api/v1/ws/scans/poll")
async def poll_scans(websocket: WebSocket):
    await connection_manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(5)
            try:
                async with aiofiles.open(DEV_ENV["templates_path"]["active_scans"], "r") as f:
                    content = await f.read()
                    if not content or content.strip() == "":
                        await websocket.send_json({"message": "No active scans"})
                        continue
                    data = json.loads(content)
                    await websocket.send_json(data)
            except json.JSONDecodeError:
                await websocket.send_json({"error": "Invalid JSON in active scans file"})
            except FileNotFoundError:
                await websocket.send_json({"error": "Active scans file not found"})
            except Exception as e:
                logger.error(f"Error reading active scans: {e}")
                await websocket.send_json({"error": "Internal server error"})
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    finally:
        connection_manager.disconnect(websocket)

@app.post("/test/tracker")
async def add_track(session:str):
    scan_tracker.add_scan(session, "http://localhost:2000", ScanStep.INIT)
    return {"data": scan_tracker.fetch_all_scans()}

@app.post("/test/tracker/fetch")
async def fetch():
    return {"data": scan_tracker.fetch_all_scans()}