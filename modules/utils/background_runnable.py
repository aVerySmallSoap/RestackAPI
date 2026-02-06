import asyncio
import json
import time
from datetime import datetime
from sqlalchemy.orm import Session

import aiofiles
from loguru import logger

from modules.analytics.ai_recosum import summarize_with_ai
from modules.analytics.vulnerability_analysis import analyze_results, generate_summary_stats, create_priority_matrix
from modules.db.database import Database
from modules.interfaces.enums.restack_enums import ScannerType, ZAPScanType, ScanStep
from modules.scanners.WapitiScanner import WapitiAdapter
from modules.scanners.discovery.WhatWebScanner import WhatWebAdapter
from modules.scanners.vulnerabilities.nuclei import NucleiAdapter
from modules.utils.__utils__ import check_url_local_test, run_start_scan, generate_random_uuid
from modules.utils.load_configs import DEV_ENV
from modules.utils.preinstances import scan_tracker
from services.managers.ScannerManager import ScannerManager

database = Database()


async def process_full_scan_job(url: str, user_id: int = None, session_id: str = None, config: dict = None):
    """
    Universal full scan processor for both manual API calls and automated scheduler jobs.

    Args:
        url: Target URL to scan
        user_id: Optional user ID for tracking
        session_id: Optional session ID (generated if not provided)
        config: Optional scan configuration

    Returns:
        dict: Scan results with session_id
    """
    # Initialize scanners
    _wapiti_scanner = WapitiAdapter()
    _nuclei_scanner = NucleiAdapter()
    local_scanner_manager = ScannerManager()
    full_scan_path = DEV_ENV["report_paths"]["full_scan"]

    # Generate session ID if not provided
    if not session_id:
        session_id = generate_random_uuid()
        logger.info(f"Generated new session ID: {session_id}")

    time_start = time.perf_counter()
    _scan_start = datetime.now()
    _URL = check_url_local_test(str(url))

    # Generate configurations
    zap_config = local_scanner_manager.generate_random_config()
    wapiti_config = _wapiti_scanner.generate_config({"modules": ["all"]})

    # Initialize tracking
    scan_tracker.add_scan(session_id, _URL, ScanStep.INIT)

    try:
        # Run ZAP scan
        logger.info(f"[{session_id}] Starting ZAP full scan...")
        zap_result, query_result, raw_whatweb_result = await asyncio.to_thread(
            run_start_scan,
            local_scanner_manager,
            _URL,
            session_id,
            scanner_type=ScannerType.ZAP,
            scan_type=ZAPScanType.FULL,
            api_key=zap_config["api_key"],
            port=zap_config["port"]
        )

        # Run Wapiti scan
        logger.info(f"[{session_id}] Starting Wapiti scan...")
        wapiti_result = await asyncio.to_thread(
            run_start_scan,
            local_scanner_manager,
            _URL,
            session_id,
            scanner_type=ScannerType.WAPITI,
            wapiti_config=wapiti_config,
            scanner_instance=_wapiti_scanner
        )

        # Run Nuclei scan
        logger.info(f"[{session_id}] Starting Nuclei scan...")
        nuclei_result = await asyncio.to_thread(
            run_start_scan,
            local_scanner_manager,
            _URL,
            session_id,
            scanner_type=ScannerType.NUCLEI,
            scanner_instance=_nuclei_scanner
        )

        # Calculate scan time
        time_end = time.perf_counter()
        scan_time = time_end - time_start

        # Analyze results
        logger.info(f"[{session_id}] Analyzing results...")
        scan_tracker.advance_step(session_id, ScanStep.ANALYZING)
        _results = analyze_results(session_id, wapiti_result, zap_result, nuclei_result, raw_whatweb_result,
                                   query_result)
        summary_stats = generate_summary_stats(_results)
        priority_matrix = create_priority_matrix(_results)
        ai_summary = summarize_with_ai(session_id)

        # Prepare response data
        data = {
            "session_id": session_id,
            "data": _results,
            "plugins": {
                "fingerprinted": raw_whatweb_result,
                "patchable": query_result if not query_result.get("error") else query_result.get("message")
            },
            "scan_time": scan_time,
            "summary": {
                "stats": summary_stats,
                "matrix": priority_matrix,
                "ai": ai_summary
            }
        }

        # Save to disk
        logger.info(f"[{session_id}] Saving results to disk...")
        scan_tracker.advance_step(session_id, ScanStep.SAVING)
        async with aiofiles.open(f"{full_scan_path}\\{session_id}.json", "w") as f:
            await f.write(json.dumps(data, indent=4))

        # Save to database
        report_id = database.insert_scan_report(
            _scan_start,
            raw_whatweb_result if query_result.get("error") else raw_whatweb_result.get("data", raw_whatweb_result),
            zap_result,
            wapiti_result,
            nuclei_result,
            _results,
            scan_time,
            _URL,
            user_id=user_id,
            summary_stats=summary_stats,
            priority_matrix=priority_matrix,
            ai_summary=ai_summary
        )

        data["id"] = report_id

        # Update final status
        scan_tracker.advance_step(session_id, ScanStep.SUCCESS)
        logger.success(f"[{session_id}] Full scan completed successfully. Report ID: {report_id}")

        return data

    except Exception as e:
        logger.error(f"[{session_id}] Full scan failed: {e}")
        scan_tracker.advance_step(session_id, ScanStep.FAILED)

        # Save error state to disk
        error_data = {
            "session_id": session_id,
            "error": str(e),
            "status": "failed"
        }
        async with aiofiles.open(f"{full_scan_path}\\{session_id}.json", "w") as f:
            await f.write(json.dumps(error_data, indent=4))

        raise


async def process_quick_scan_job(url: str, user_id: int = None, session_id: str = None, config: dict = None):
    """
    Universal quick scan (Wapiti only) processor for both manual API calls and automated jobs.

    Args:
        url: Target URL to scan
        user_id: Optional user ID for tracking
        session_id: Optional session ID (generated if not provided)
        config: Optional scan configuration

    Returns:
        dict: Scan results with session_id
    """
    # Initialize scanners
    _wapiti_scanner = WapitiAdapter()
    _whatweb_scanner = WhatWebAdapter()
    local_scanner_manager = ScannerManager()
    quick_scan_path = DEV_ENV["report_paths"].get("quick_scan", DEV_ENV["report_paths"]["full_scan"])

    # Generate session ID if not provided
    if not session_id:
        session_id = generate_random_uuid()
        logger.info(f"Generated new session ID: {session_id}")

    time_start = time.perf_counter()
    _scan_start = datetime.now()
    _URL = check_url_local_test(str(url))

    # Generate configuration
    wapiti_config = _wapiti_scanner.generate_config({"modules": ["all"]})

    # Initialize tracking
    scan_tracker.add_scan(session_id, _URL, ScanStep.INIT)

    try:
        # Run Wapiti scan
        logger.info(f"[{session_id}] Starting Wapiti quick scan...")
        result = await asyncio.to_thread(
            run_start_scan,
            local_scanner_manager,
            _URL,
            session_id,
            scanner_type=ScannerType.WAPITI,
            wapiti_config=wapiti_config,
            scanner_instance=_wapiti_scanner
        )

        # Run WhatWeb scan
        logger.info(f"[{session_id}] Starting WhatWeb scan...")
        scan_tracker.advance_step(session_id, ScanStep.WHATWEB)
        _whatweb_results, _query_results = await _whatweb_scanner.start_scan(_URL, session_id)

        scan_tracker.advance_step(session_id, ScanStep.CLEANUP)
        scan_time = time.perf_counter() - time_start

        # Prepare response data
        data = {
            "session_id": session_id,
            "data": result,
            "plugins": {
                "fingerprinted": _whatweb_results if _whatweb_results.get("error") else _whatweb_results.get("data"),
                "patchable": _query_results
            },
            "scan_time": scan_time
        }

        # Save to disk
        logger.info(f"[{session_id}] Saving results to disk...")
        scan_tracker.advance_step(session_id, ScanStep.SAVING)
        async with aiofiles.open(f"{quick_scan_path}\\{session_id}.json", "w") as f:
            await f.write(json.dumps(data, indent=4))

        # Save to database
        report_id = database.insert_wapiti_quick_report(
            _scan_start,
            _whatweb_results if _whatweb_results.get("error") else _whatweb_results.get("data"),
            result,
            scan_time,
            _URL,
            user_id=user_id
        )

        data["id"] = report_id

        # Update final status
        scan_tracker.advance_step(session_id, ScanStep.SUCCESS)
        logger.success(f"[{session_id}] Quick scan completed successfully. Report ID: {report_id}")

        return data

    except Exception as e:
        logger.error(f"[{session_id}] Quick scan failed: {e}")
        scan_tracker.advance_step(session_id, ScanStep.FAILED)

        # Save error state to disk
        error_data = {
            "session_id": session_id,
            "error": str(e),
            "status": "failed"
        }
        async with aiofiles.open(f"{quick_scan_path}\\{session_id}.json", "w") as f:
            await f.write(json.dumps(error_data, indent=4))

        raise


# Legacy function for backward compatibility with scheduler
async def run_scheduled_scan(url: str, user_id=None):
    """
    Legacy wrapper for scheduled scans. Calls the new centralized function.
    """
    logger.info(f"Starting scheduled full scan for {url}")
    try:
        await process_full_scan_job(url, user_id=user_id)
        logger.success(f"Scheduled scan completed for {url}")
    except Exception as e:
        logger.error(f"Scheduled scan failed for {url}: {e}")