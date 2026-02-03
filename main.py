import asyncio
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from sqlalchemy.orm import Session
from urllib.parse import urlparse

import aiofiles
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from loguru import logger
from pydantic import BaseModel, AnyUrl

from modules.analytics.ai_recosum import summarize_with_ai
from modules.analytics.formal.descriptive import get_general_analytics, get_raw_vulnerabilities
from modules.analytics.formal.pareto_80_20 import pareto_vulnerability_analysis
from modules.analytics.formal.correlation_regression import vulnerability_correlation_analysis, \
    regression_vulnerability_prediction
from modules.analytics.formal.probability_fitting_distribution import vulnerability_distribution_analysis
from modules.analytics.informal.activity_summary import get_scan_activity_summary
from modules.analytics.informal.time_series import calculate_time_series
from modules.analytics.vulnerability_analysis import analyze_results, generate_summary_stats, create_priority_matrix
from modules.db.database import Database
from modules.db.table_collection import ScheduledScans, Scan
from modules.interfaces.enums.restack_enums import ZAPScanType, ScannerType, ScanStep
from modules.scanners.WapitiScanner import WapitiAdapter
from modules.scanners.discovery.WhatWebScanner import WhatWebAdapter
from modules.scanners.vulnerabilities.nuclei import NucleiAdapter
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
scanner_manager = ScannerManager()
check_directories()
logger.add("./logs/{time}.log", rotation="10MB", enqueue=True)


@asynccontextmanager
async def lifespan(api: FastAPI):
    global _schedule_manager
    _schedule_manager = ScheduleManager(_db)
    yield


def get_scheduler_service():
    if _schedule_manager is None:
        raise HTTPException(status_code=500, detail="Scheduler not initialized")
    return _schedule_manager

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: AnyUrl
    user_id: int | None = None
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
        scanner_manager,
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
            _URL,
            user_id=request.user_id
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
            _URL,
            user_id=request.user_id
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
    zap_config = scanner_manager.generate_random_config()
    scan_tracker.add_scan(session, _URL, ScanStep.INIT)

    zap_result, query_result, raw_whatweb_result = await asyncio.to_thread(
        run_start_scan,
        scanner_manager,
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
            _URL,
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
    zap_config = scanner_manager.generate_random_config()
    scan_tracker.add_scan(session, _URL, ScanStep.INIT)

    zap_result, query_result, raw_whatweb_result = await asyncio.to_thread(
        run_start_scan,
        scanner_manager,
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
    _nuclei_scanner = NucleiAdapter()
    _wapiti_scanner = WapitiAdapter()
    full_scan_path = DEV_ENV["report_paths"]["full_scan"]
    time_start = time.perf_counter()
    _scan_start = datetime.now()
    _URL = check_url_local_test(str(request.url))
    session = scan_tracker.generate_unique_session()
    zap_config = scanner_manager.generate_random_config()
    wapiti_config = _wapiti_scanner.generate_config(
        {
            "modules": ["all"]
        }
    )
    scan_tracker.add_scan(session, _URL, ScanStep.INIT)

    zap_result, query_result, raw_whatweb_result = await asyncio.to_thread(
        run_start_scan,
        scanner_manager,
        _URL,
        session,
        scanner_type=ScannerType.ZAP,
        scan_type=ZAPScanType.FULL,
        api_key=zap_config["api_key"],
        port=zap_config["port"]
    )

    wapiti_result = await asyncio.to_thread(
        run_start_scan,
        scanner_manager,
        _URL,
        session,
        scanner_type=ScannerType.WAPITI,
        wapiti_config=wapiti_config,
        scanner_instance=_wapiti_scanner
    )

    nuclei_result = await asyncio.to_thread(
        run_start_scan,
        scanner_manager,
        _URL,
        session,
        scanner_type=ScannerType.NUCLEI,
        scanner_instance=_nuclei_scanner
    )

    time_end = time.perf_counter()
    scan_time = time_end - time_start

    # Analytics
    scan_tracker.advance_step(session, ScanStep.ANALYZING)
    _results = analyze_results(session, wapiti_result, zap_result, nuclei_result, raw_whatweb_result, query_result)
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

    # Save report in disk
    scan_tracker.advance_step(session, ScanStep.SAVING)
    f = await aiofiles.open(f"{full_scan_path}\\{session}.json", "w")
    await f.write(json.dumps(data, indent=4))
    await f.close()

    # DB write
    if query_result.__contains__("error"):
        _db.insert_scan_report(
            _scan_start,
            raw_whatweb_result,
            zap_result,
            wapiti_result,
            nuclei_result,
            _results,
            scan_time,
            _URL,
            user_id=request.user_id
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
            nuclei_result,
            _results,
            scan_time,
            _URL,
            user_id=request.user_id
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
            await asyncio.sleep(5)  # Poll database every 5 seconds
            try:
                # Use asyncio.to_thread because database access is blocking
                active_scans = await asyncio.to_thread(scan_tracker.fetch_all_scans)

                if not active_scans:
                    await websocket.send_json({"message": "No active scans"})
                else:
                    await websocket.send_json(active_scans)

            except Exception as e:
                logger.error(f"Error polling active scans: {e}")
                await websocket.send_json({"error": "Internal server error"})
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    finally:
        connection_manager.disconnect(websocket)


@app.post("/test/tracker")
async def add_track(session: str):
    scan_tracker.add_scan(session, "http://localhost:2000", ScanStep.INIT)
    return {"data": scan_tracker.fetch_all_scans()}


@app.post("/test/tracker/fetch")
async def fetch():
    return {"data": scan_tracker.fetch_all_scans()}


@app.get("/test/poll/data/summary/{days}")
async def poll_data_summary(
    days: int,
    target: str = Query(None, description="Filter by target domain")
):
    # Pass the target to the function
    return get_scan_activity_summary(days, target_domain=target)


@app.get("/api/v1/analytics/vulnerabilities")
async def get_vulnerabilities_list(
    target: str = Query(None),
    start: str = Query(None),
    end: str = Query(None)
):
    """
    Get raw vulnerability list for the data table
    """
    try:
        with Session(_db.engine) as session:
            return get_raw_vulnerabilities(
                session,
                target_domain=target,
                start_date=start,
                end_date=end
            )
    except Exception as e:
        logger.error(f"Failed to fetch vulnerability list: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/analytics/dashboard")
async def get_dashboard_data(
    target: str = Query(None, description="Filter by target domain"),
    start: str = Query(None, description="YYYY-MM-DD"),
    end: str = Query(None, description="YYYY-MM-DD")
):
    try:
        with Session(_db.engine) as session:
            return get_general_analytics(
                session,
                target_domain=target,
                start_date=start,
                end_date=end
            )
    except Exception as e:
        logger.error(f"Analytics error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/analytics/descriptive")
async def get_descriptive_analytics(
        mode: str = Query("snapshot"),
        target: str = Query(None),
        start: str = Query(None),
        end: str = Query(None)
):
    try:
        with Session(_db.engine) as session:
            # You will need to update get_descriptive_stats to accept start/end too
            stats = get_descriptive_stats(session, mode=mode, target_domain=target, start_date=start, end_date=end)
            return stats
    except Exception as e:
        logger.error(f"Failed to generate descriptive stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/analytics/executive")
async def get_executive_report(
    target: str = Query(None, description="Filter by target domain (e.g., example.com)"),
    days: int = Query(90, description="Lookback period for stability analysis")
):
    """
    Returns the 'External Posture & Compliance' Scorecard.
    This endpoint separates high-confidence compliance findings from unverified leads.
    """
    try:
        # Use the global _db object initialized in main.py
        with Session(_db.engine) as session:
            return get_executive_analytics(
                session,
                target_domain=target,
                days=days
            )
    except Exception as e:
        logger.error(f"Failed to generate executive report: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/test/poll/data/pareto")
async def poll_data_pareto(target: str = Query(None, description="Filter by target domain")):
    """Get Pareto analysis of vulnerabilities, optionally filtered by domain"""
    try:
        return pareto_vulnerability_analysis(target_domain=target)
    except Exception as e:
        logger.error(f"Failed to generate Pareto analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/test/poll/data/arrima")
async def poll_data_arrima(target: AnyUrl, forecast_days: int):
    return arima_vulnerability_forecast(target.host, forecast_days)



@app.get("/test/poll/data/timeseries")
async def poll_data_timeseries(
    target: AnyUrl = Query(..., description="Target URL"),
    days: int = 90,
    start: str = Query(None, description="Start date (YYYY-MM-DD)"),
    end: str = Query(None, description="End date (YYYY-MM-DD)")
):
    return calculate_time_series(target, days, start_date=start, end_date=end)


@app.get("/test/poll/data/correlation")
async def poll_data_correlation(target: str = Query(None, description="Filter by target domain")):
    """Get correlation analysis, optionally filtered by domain"""
    try:
        return vulnerability_correlation_analysis(target_domain=target)
    except Exception as e:
        logger.error(f"Failed to generate correlation analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/test/poll/data/distribution")
async def poll_data_distribution(
        report_id: str = Query(None, description="Filter by specific report ID"),
        target: str = Query(None, description="Filter by target domain")
):
    """Get distribution analysis, optionally filtered by report or domain"""
    try:
        return vulnerability_distribution_analysis(report_id=report_id, target_domain=target)
    except Exception as e:
        logger.error(f"Failed to generate distribution analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/test/poll/data/regression")
async def poll_data_regression(target: str = Query(None, description="Filter by target domain")):
    """Get regression prediction model, optionally filtered by domain"""
    try:
        return regression_vulnerability_prediction(target_domain=target)
    except Exception as e:
        logger.error(f"Failed to generate regression analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/analytics/targets")
async def get_analytics_targets():
    """Get list of all unique target domains from scans"""
    try:
        with Session(_db.engine) as session:
            # Get all unique target URLs
            target_urls = session.query(Scan.target_url).distinct().all()

            # Extract domains from URLs
            domains = set()
            for url_tuple in target_urls:
                url = url_tuple[0]
                try:
                    parsed = urlparse(url)
                    # Get netloc (hostname with port if present)
                    domain = parsed.netloc or parsed.path.split('/')[0]
                    # Remove port if present
                    domain = domain.split(':')[0]
                    if domain:
                        domains.add(domain)
                except Exception as e:
                    logger.warning(f"Failed to parse URL {url}: {e}")
                    continue

            return {
                "domains": sorted(list(domains)),
                "count": len(domains)
            }
    except Exception as e:
        logger.error(f"Failed to fetch analytics targets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# @app.post("/v1/schedule/add")
# async def add_schedule(schedule: ScheduleRequest):
#     """Add a new scheduled scan"""
#     try:
#         manager = get_scheduler_service()
#         manager.add_schedule_scan(
#             schedule.name,
#             schedule.job_type,
#             schedule.target.__str__(),
#             schedule.interval
#         )
#         return {"message": "Schedule added successfully"}
#     except Exception as e:
#         logger.error(f"Failed to add schedule: {e}")
#         raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/schedule/add")
async def add_schedule(schedule: ScheduleRequest):
    """Add a new scheduled scan - scheduler_service.py will pick it up"""
    try:
        # Just write to database, don't use APScheduler here
        schedule_id = str(uuid.uuid4())

        with Session(_db.engine) as session:
            new_scan = ScheduledScans(
                id=schedule_id,
                url=str(schedule.target),
                codename=schedule.name,
                job_type=schedule.job_type,
                configuration=schedule.interval,
            )
            session.add(new_scan)
            session.commit()
        return {
            "message": "Schedule added successfully. It will be picked up by the scheduler service.",
            "schedule_id": schedule_id
        }
    except Exception as e:
        logger.error(f"Failed to add schedule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# @app.get("/v1/schedules/")
# async def get_schedules():
#     """Get all scheduled scans"""
#     try:
#         with Session(_db.engine) as session:
#             data = session.query(ScheduledScans).all()
#             return data
#     except Exception as e:
#         logger.error(f"Failed to fetch schedules: {e}")
#         raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/schedules/")
async def get_schedules():
    """Get all scheduled scans"""
    try:
        with Session(_db.engine) as session:
            schedules = session.query(ScheduledScans).all()

            result = []
            for s in schedules:
                result.append({
                    "id": s.id,
                    "name": s.codename,
                    "target": s.url,
                    "job_type": s.job_type,
                    "configuration": s.configuration
                })

            return {
                "schedules": result,
                "count": len(result)
            }
    except Exception as e:
        logger.error(f"Failed to fetch schedules: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/schedule/{schedule_id}")
async def get_schedule(schedule_id: str):
    """Get a specific scheduled scan by ID"""
    try:
        with Session(_db.engine) as session:
            schedule = session.query(ScheduledScans).filter(
                ScheduledScans.id == schedule_id
            ).first()

            if not schedule:
                raise HTTPException(
                    status_code=404,
                    detail=f"Schedule with ID '{schedule_id}' not found"
                )

            return {
                "id": schedule.id,
                "name": schedule.codename,
                "target": schedule.url,
                "job_type": schedule.job_type,
                "configuration": schedule.configuration
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch schedule {schedule_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# @app.put("/v1/schedule/{schedule_id}")
# async def update_schedule(schedule_id: str, schedule: ScheduleRequest):
#     """Update an existing scheduled scan"""
#     try:
#         manager = get_scheduler_service()
#         manager.update_schedule(
#             schedule_id,
#             schedule.name,
#             schedule.job_type,
#             schedule.target.__str__(),
#             schedule.interval
#         )
#         return {"message": "Schedule updated successfully"}
#     except Exception as e:
#         logger.error(f"Failed to update schedule {schedule_id}: {e}")
#         raise HTTPException(status_code=500, detail=str(e))


@app.put("/v1/schedule/{schedule_id}")
async def update_schedule(schedule_id: str, schedule: ScheduleRequest):
    """Update an existing scheduled scan"""
    try:
        # Validate interval configuration
        if schedule.job_type not in ["interval", "cron"]:
            raise HTTPException(
                status_code=400,
                detail="job_type must be 'interval' or 'cron'"
            )

        with Session(_db.engine) as session:
            existing_schedule = session.query(ScheduledScans).filter(
                ScheduledScans.id == schedule_id
            ).first()

            if not existing_schedule:
                raise HTTPException(
                    status_code=404,
                    detail=f"Schedule with ID '{schedule_id}' not found"
                )

            # Check if new name conflicts with another schedule
            name_conflict = session.query(ScheduledScans).filter(
                ScheduledScans.codename == schedule.name,
                ScheduledScans.id != schedule_id
            ).first()

            if name_conflict:
                raise HTTPException(
                    status_code=400,
                    detail=f"Schedule with name '{schedule.name}' already exists"
                )

            # Update fields
            existing_schedule.codename = schedule.name
            existing_schedule.url = str(schedule.target)
            existing_schedule.job_type = schedule.job_type
            existing_schedule.configuration = schedule.interval

            session.commit()

        logger.info(f"Schedule updated: {schedule.name} ({schedule_id})")
        return {
            "message": "Schedule updated successfully",
            "schedule_id": schedule_id
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update schedule {schedule_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# @app.delete("/v1/schedule/{schedule_id}")
# async def delete_schedule(schedule_id: str):
#     """Delete a scheduled scan"""
#     try:
#         manager = get_scheduler_service()
#         manager.delete_schedule(schedule_id)
#         return {"message": "Schedule deleted successfully"}
#     except Exception as e:
#         logger.error(f"Failed to delete schedule {schedule_id}: {e}")
#         raise HTTPException(status_code=404, detail=str(e))

@app.delete("/v1/schedule/{schedule_id}")
async def delete_schedule(schedule_id: str):
    """Delete a scheduled scan"""
    try:
        with Session(_db.engine) as session:
            schedule = session.query(ScheduledScans).filter(
                ScheduledScans.id == schedule_id
            ).first()

            if not schedule:
                raise HTTPException(
                    status_code=404,
                    detail=f"Schedule with ID '{schedule_id}' not found"
                )

            schedule_name = schedule.codename
            session.delete(schedule)
            session.commit()

        logger.info(f"Schedule deleted: {schedule_name} ({schedule_id})")
        return {
            "message": "Schedule deleted successfully",
            "schedule_id": schedule_id
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete schedule {schedule_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/schedules/search")
async def search_schedules(
        name: str = Query(None, description="Search by schedule name"),
        target: str = Query(None, description="Search by target URL"),
        job_type: str = Query(None, description="Filter by job type (interval/cron)")
):
    """Search schedules with optional filters"""
    try:
        with Session(_db.engine) as session:
            query = session.query(ScheduledScans)

            # Apply filters
            if name:
                query = query.filter(ScheduledScans.codename.ilike(f"%{name}%"))
            if target:
                query = query.filter(ScheduledScans.url.ilike(f"%{target}%"))
            if job_type:
                if job_type not in ["interval", "cron"]:
                    raise HTTPException(
                        status_code=400,
                        detail="job_type must be 'interval' or 'cron'"
                    )
                query = query.filter(ScheduledScans.job_type == job_type)

            schedules = query.all()

            result = []
            for s in schedules:
                result.append({
                    "id": s.id,
                    "name": s.codename,
                    "target": s.url,
                    "job_type": s.job_type,
                    "configuration": s.configuration
                })

            return {
                "schedules": result,
                "count": len(result),
                "filters": {
                    "name": name,
                    "target": target,
                    "job_type": job_type
                }
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to search schedules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/v1/history/{report_id}")
async def delete_history_report(report_id: str):
    """Delete a scan history report and its associated vulnerabilities"""
    try:
        result = await asyncio.to_thread(_db.delete_report, report_id)
        if result:
            return {"message": "Report deleted successfully"}
        else:
            raise HTTPException(status_code=404, detail="Report not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete report {report_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))