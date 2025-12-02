import asyncio
import json
import time
from datetime import datetime
from sqlalchemy.orm import Session

import aiofiles

from modules.analytics.vulnerability_analysis import analyze_results
from modules.db.database import Database
from modules.db.table_collection import ActiveScan
from modules.interfaces.enums.restack_enums import ScannerType, ZAPScanType, ScanStep
from modules.scanners.WapitiScanner import WapitiAdapter
from modules.utils.__utils__ import check_url_local_test, run_start_scan
from modules.utils.load_configs import DEV_ENV
from modules.utils.preinstances import scan_tracker
from services.managers.ScannerManager import ScannerManager

database = Database()

async def run_scheduled_scan(url):
    # Init
    _wapiti_scanner = WapitiAdapter()
    full_scan_path = DEV_ENV["report_paths"]["full_scan"]

    local_scanner_manager = ScannerManager()

    time_start = time.perf_counter()
    _scan_start = datetime.now()
    _URL = check_url_local_test(str(url))
    session_id = scan_tracker.generate_unique_session()
    zap_config = local_scanner_manager.generate_random_config()
    wapiti_config = _wapiti_scanner.generate_config(
        {
            "modules": ["all"]
        }
    )
    scan_tracker.add_scan(session_id, _URL, ScanStep.INIT)

    with Session(database.engine) as session:
        isPresent = session.query(ActiveScan).where(ActiveScan.session_id == session_id).scalar()
        print(isPresent)
        if isPresent:
            return

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

    wapiti_result = await asyncio.to_thread(
        run_start_scan,
        local_scanner_manager,
        _URL,
        session_id,
        scanner_type=ScannerType.WAPITI,
        wapiti_config=wapiti_config,
        scanner_instance=_wapiti_scanner
    )

    # Analytics
    scan_tracker.advance_step(session_id, ScanStep.ANALYZING)
    _results = analyze_results(session_id, wapiti_result, zap_result, raw_whatweb_result, query_result)

    time_end = time.perf_counter()
    scan_time = time_end - time_start

    # DB write
    scan_tracker.advance_step(session_id, ScanStep.SAVING)
    if query_result.__contains__("error"):
        f = await aiofiles.open(f"{full_scan_path}\\{session_id}.json", "w")
        await f.write(json.dumps(
            {
                "data": _results,
                "plugins": {
                    "fingerprinted": raw_whatweb_result,
                    "patchable": query_result
                },
                "scan_time": scan_time
            },
            indent=4)
        )
        await f.close()

        database.insert_automated_report(
            _scan_start,
            raw_whatweb_result,
            zap_result,
            wapiti_result,
            _results,
            scan_time,
            _URL
        )
    else:
        f = await aiofiles.open(f"{full_scan_path}\\{session_id}.json", "w")
        await f.write(json.dumps(
            {
                "data": _results,
                "plugins": {
                    "fingerprinted": raw_whatweb_result["data"],
                    "patchable": query_result
                },
                "scan_time": scan_time
            },
            indent=4)
        )
        await f.close()

        database.insert_automated_report(
            _scan_start,
            raw_whatweb_result["data"],
            zap_result,
            wapiti_result,
            _results,
            scan_time,
            _URL
        )