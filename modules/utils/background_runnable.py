import asyncio
import json
import time
from datetime import datetime

import aiofiles

from modules.analytics.vulnerability_analysis import analyze_results
from modules.db.database import Database
from modules.interfaces.enums.restack_enums import ScannerType, ZAPScanType
from modules.scanners.WapitiScanner import WapitiAdapter
from modules.utils.__utils__ import check_url_local_test, run_start_scan
from modules.utils.load_configs import DEV_ENV


async def run_scheduled_scan(scanner_manager, request, database: Database):
    # Init
    _wapiti_scanner = WapitiAdapter()
    full_scan_path = DEV_ENV["report_paths"]["full_scan"]

    time_start = time.perf_counter()
    _scan_start = datetime.now()
    _URL = check_url_local_test(str(request.url))
    session = scanner_manager.generate_unique_session()
    zap_config = scanner_manager.generate_random_config()
    wapiti_config = _wapiti_scanner.generate_config(
        {
            "modules": ["all"]
        }
    )

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

    # Analytics
    _results = analyze_results(session, wapiti_result, zap_result)

    time_end = time.perf_counter()
    scan_time = time_end - time_start

    # DB write
    if query_result.__contains__("error"):
        f = await aiofiles.open(f"{full_scan_path}\\{session}.json", "w")
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

        database.insert_scan_report(
            _scan_start,
            raw_whatweb_result,
            zap_result,
            wapiti_result,
            _results,
            scan_time,
            _URL
        )
    else:
        f = await aiofiles.open(f"{full_scan_path}\\{session}.json", "w")
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

        database.insert_scan_report(
            _scan_start,
            raw_whatweb_result["data"],
            zap_result,
            wapiti_result,
            _results,
            scan_time,
            _URL
        )
