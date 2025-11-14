import asyncio
import json
import time
from datetime import datetime

import aiofiles
from modules.analytics.vulnerability_analysis import analyze_results
from modules.db.database import Database
from modules.interfaces.enums.ScanTypes import ScanType
from modules.interfaces.enums.ScannerTypes import ScannerTypes
from modules.interfaces.enums.ZAPScanTypes import ZAPScanTypes
from modules.scanners.WapitiScanner import WapitiAdapter
from modules.scanners.WhatWebScanner import WhatWebAdapter
from modules.scanners.ZapScanner import ZapAdapter
from modules.utils.DEV_utils import check_url_local_test
from modules.utils.docker_utils import vuln_search_query, parse_query
from modules.utils.load_configs import DEV_ENV
from services.ScannerEngine import ScannerEngine

async def _start_automatic_scan(scanner_engine: ScannerEngine, url, database: Database):
    print("Starting automatic scan")
    time_start = time.perf_counter()
    # init
    _scan_start = datetime.now()
    _whatweb_scanner = WhatWebAdapter()
    scanner_engine.enqueue_session(ScannerTypes.FULL, _scan_start)
    session_name = scanner_engine.dequeue_name()  # Get the latest time session and use it as the file name
    _zap_path = f"{DEV_ENV['report_paths']['zap']}\\{session_name}.json"
    _wapiti_path = f"{DEV_ENV['report_paths']['wapiti']}\\{session_name}.json"
    _whatweb_path = f"{DEV_ENV['report_paths']['whatweb']}\\{session_name}.json"

    # Generate config dictionaries
    _wapiti_config_generator = WapitiAdapter()
    config = _wapiti_config_generator.generate_config({"path": _wapiti_path, "modules": ["all"]})

    # WhatWeb scan
    _URL = check_url_local_test(str(url))
    await _whatweb_scanner.start_automatic_scan(_URL, session_name)
    _whatweb_result = _whatweb_scanner.parse_results(_whatweb_path)


    _zap_result, _wapiti_result, _query_result, _results = await asyncio.to_thread(
        _run_blocking_scans_and_analysis,
        url,
        session_name,
        _zap_path,
        _wapiti_path,
        _whatweb_result,
        config
    )

    time_end = time.perf_counter()
    scan_time = time_end - time_start

    # Save report in disk
    f = await aiofiles.open(f"{DEV_ENV['report_paths']['full_scan']}\\{session_name}.json", "w")
    await f.write(json.dumps(
        {"data": _results, "plugins": {"fingerprinted": _whatweb_result["data"], "patchable": _query_result},
         "scan_time": scan_time}, indent=4))
    await f.close()

    # DB write
    await asyncio.to_thread(
        database.insert_scan_report,
        _scan_start,
        f"{DEV_ENV['report_paths']['full_scan']}\\{session_name}.json",
        _whatweb_result["data"],
        _zap_result,
        _wapiti_result,
        _results,
        scan_time,
        _URL
    )

def _run_blocking_scans_and_analysis(url, session_name, zap_path, wapiti_path, whatweb_results, config):
    _zap_scanner = ZapAdapter({"apikey": "test"})
    _wapiti_scanner = WapitiAdapter()
    _URL = check_url_local_test(str(url))

    # Zap scan
    _zap_scanner.start_scan(_URL, {"path": zap_path, "scan_type": ZAPScanTypes.AUTOMATIC, "apikey": "test", "port":9100, "session_name": session_name})
    _zap_result = _zap_scanner.parse_results(zap_path)

    # Wapiti scan
    _wapiti_scanner.start_automatic_scan(_URL, config)
    _wapiti_result = _wapiti_scanner.parse_results(wapiti_path)

    _query_results = {}
    if len(whatweb_results["data"][0]) > 0 or whatweb_results["data"][0] is not None:
        has_results = vuln_search_query(whatweb_results["data"][0], session_name)
        if has_results:
            _query_results = parse_query(session_name)
        else:
            _query_results = None
    else:
        _query_results = None

    _results = analyze_results(session_name, _wapiti_result, _zap_result)
    return _zap_result, _wapiti_result, _query_results, _results


async def scheduled_scan(scanner_engine, request, database):
    await _start_automatic_scan(scanner_engine, request, database)