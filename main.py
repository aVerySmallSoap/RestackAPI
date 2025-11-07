import time
from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, AnyUrl

from modules.db.database import Database
from modules.interfaces.enums.ScanTypes import ScanType
from modules.interfaces.enums.ZAPScanTypes import ZAPScanTypes
from modules.interfaces.enums.ScannerTypes import ScannerTypes
from modules.scanners.WapitiScanner import WapitiAdapter
from modules.scanners.WhatWebAdapter import WhatWebAdapter
from modules.scanners.ZapScanner import ZapAdapter
from modules.utils.load_configs import DEV_ENV
from services.ScannerEngine import ScannerEngine
from modules.utils.docker_utils import start_manual_zap_service
from modules.utils.check_dir import check_directories

# == TESTING MODULES ==
from modules.utils.DEV_utils import check_url_local_test

# == END OF TESTING MODULES==

# == TEST WEBSITES ==
# https://public-firing-range.appspot.com
# https://github.com/WebGoat/WebGoat
# https://github.com/juice-shop/juice-shop
# == END OF TESTING WEBSITES ==

_db = Database()
start_manual_zap_service({"apikey": "test"})
_scannerEngine = ScannerEngine()
check_directories()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
)

class ScanRequest(BaseModel):
    url: AnyUrl
    config: dict|None = None

@app.post("/api/v1/wapiti/scan/quick")
async def wapiti_scan(request: ScanRequest) -> dict:
    """Starts a configured wapiti scan"""
    time_start = time.perf_counter()
    # init
    _scan_start = datetime.now()
    _wapiti_scanner = WapitiAdapter()
    _whatweb_scanner = WhatWebAdapter()
    _scannerEngine.enqueue_session(ScannerTypes.WAPITI, _scan_start)
    session_name = _scannerEngine.dequeue_name() # Get the latest time session and use it as the file name
    _whatweb_path = f"{DEV_ENV['report_paths']['whatweb']}\\{session_name}.json"
    _wapiti_path = f"{DEV_ENV['report_paths']['wapiti']}\\{session_name}.json"
    config = _wapiti_scanner.generate_config({"path": _wapiti_path, "modules": ["all"]})
    # scanning
    _URL = check_url_local_test(str(request.url))
    _wapiti_scanner.start_scan(_URL, ScanType.QUICK, config)
    report = _wapiti_scanner.parse_results(_wapiti_path)  # TODO: Change how the DB reads this
    await _whatweb_scanner.start_scan(_URL, {"path": _whatweb_path})
    _whatweb_results = _whatweb_scanner.parse_results(_wapiti_path)
    time_end = time.perf_counter()
    scan_time = time_end - time_start
    _db.insert_wapiti_quick_report(_scan_start, _wapiti_path, _whatweb_results["raw"], report, scan_time) # Rewrite reading of report variable
    if not _whatweb_results.__contains__("error"):
        return {"data": report, "plugins": _whatweb_results["data"], "scan_time": scan_time}
    else:
        return {"data": report, "plugins": _whatweb_results, "scan_time": scan_time}


@app.post("/api/v1/wapiti/scan/full")
async def wapiti_scan_full(request: ScanRequest) -> dict:
    """Launches a wapiti scan with user-defined configurations"""
    pass

#TODO: Active and Passive scanning should be collapsed into a singular endpoint, the scan type should be defined in ScanRequest.config.scanType
@app.post("/api/v1/zap/scan/passive")
async def zap_passive_scan(request: ScanRequest) -> dict:
    """Starts a passive zap scan"""
    time_start = time.perf_counter()
    # init
    _scan_start = datetime.now()
    _zap_scanner = ZapAdapter({"apikey": "test"})
    _whatweb_scanner = WhatWebAdapter()
    _scannerEngine.enqueue_session(ScannerTypes.ZAP, _scan_start)
    session_name = _scannerEngine.dequeue_name() # Get the latest time session and use it as the file name
    _zap_path = f"{DEV_ENV['report_paths']['zap']}\\{session_name}.json"
    _whatweb_path = f"{DEV_ENV['report_paths']['whatweb']}\\{session_name}.json"
    # scanning
    _URL = check_url_local_test(str(request.url))
    _zap_scanner.start_scan(_URL, {"path": _zap_path, "scan_type": ZAPScanTypes.PASSIVE, "apikey": "test"})
    report = _zap_scanner.parse_results(_zap_path)
    await _whatweb_scanner.start_scan(_URL, {"path": _whatweb_path})
    _whatweb_results = _whatweb_scanner.parse_results(_whatweb_path)
    time_end = time.perf_counter()
    scan_time = time_end - time_start
    _db.insert_zap_report(_scan_start, _zap_path, _whatweb_results["data"], report, scan_time, _URL)
    if not _whatweb_results.__contains__("error"):
        return {"data": report, "plugins": _whatweb_results["data"], "scan_time": scan_time}
    else:
        return {"data": report, "plugins": _whatweb_results, "scan_time": scan_time}


@app.post("/api/v1/zap/scan/active")
async def zap_active_scan(request: ScanRequest) -> dict:
    """Starts an active zap scan"""
    time_start = time.perf_counter()
    # init
    _scan_start = datetime.now()
    _zap_scanner = ZapAdapter({"apikey": "test"})
    _whatweb_scanner = WhatWebAdapter()
    _scannerEngine.enqueue_session(ScannerTypes.ZAP, _scan_start)
    session_name = _scannerEngine.dequeue_name() # Get the latest time session and use it as the file name
    _zap_path = f"{DEV_ENV['report_paths']['zap']}\\{session_name}.json"
    _whatweb_path = f"{DEV_ENV['report_paths']['whatweb']}\\{session_name}.json"
    # scanning
    _URL = check_url_local_test(str(request.url))
    _zap_scanner.start_scan(_URL, {"path": _zap_path, "scan_type": ZAPScanTypes.ACTIVE, "apikey": "test"})
    report = _zap_scanner.parse_results(_zap_path)
    await _whatweb_scanner.start_scan(_URL, {"path": _whatweb_path})
    _whatweb_results = _whatweb_scanner.parse_results(_whatweb_path)
    time_end = time.perf_counter()
    scan_time = time_end - time_start
    _db.insert_zap_report(_scan_start, _zap_path, _whatweb_results["data"], report, scan_time, _URL)
    if not _whatweb_results.__contains__("error"):
        return {"data": report, "plugins": _whatweb_results["data"], "scan_time": scan_time}
    else:
        return {"data": report, "plugins": _whatweb_results, "scan_time": scan_time}

@app.post("/api/v1/zap/scan/full")
async def zap_full_scan(request: ScanRequest) -> dict:
    """Starts both a passive and active zap scan with user-defined configurations"""
    pass

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
    session_name = _scannerEngine.dequeue_name() # Get the latest time session and use it as the file name
    _zap_path = f"{DEV_ENV['report_paths']['zap']}\\{session_name}.json"
    _wapiti_path = f"{DEV_ENV['report_paths']['wapiti']}\\{session_name}.json"
    _whatweb_path = f"{DEV_ENV['report_paths']['whatweb']}\\{session_name}.json"
    config = _wapiti_scanner.generate_config({"path": _wapiti_path, "modules": ["all"]})
    # scanning
    _URL = check_url_local_test(str(request.url)) # Check if the app is hosted locally
    # url_context = zap.pscan.urls(url) # extract zap crawl and seed wapiti
    # Zap scan
    _zap_scanner.start_scan(_URL, {"path": _zap_path, "scan_type": ZAPScanTypes.ACTIVE, "apikey": "test"})
    _zap_result = _zap_scanner.parse_results(_zap_path)
    # Wapiti scan
    _wapiti_scanner.start_scan(_URL, ScanType.QUICK, config)
    _wapiti_result = _wapiti_scanner.parse_results(_wapiti_path)
    # WhatWeb scan
    await _whatweb_scanner.start_scan(_URL, {"path": _whatweb_path})
    _whatweb_results = _whatweb_scanner.parse_results(_whatweb_path)
    # SearchVulns Query
        # TODO: Implement
        # vulnerable_tech = tech_cve_query(_whatweb_results)
    # Analytics
        # TODO: Implement
        # combined_results = analyze(_zap_result, _wapiti_result)
    # DB write
        # TODO: write to database
    time_end = time.perf_counter()
    scan_time = time_end - time_start
        # TODO: Implement
    if not _whatweb_results.__contains__("error"):
        # TODO: "merged" should contain be combined_results from the analytics of both zap and wapiti results
        return {"data": {"compiled": [_zap_result, _wapiti_result], "merged": ""}, "plugins": {"fingerprinted": _whatweb_results["data"], "patchable": ""}, "scan_time": scan_time}
    else:
        return {"data": {"compiled": [_zap_result, _wapiti_result], "merged": ""}, "plugins": {"fingerprinted": _whatweb_results, "patchable": ""}, "scan_time": scan_time}

@app.post("/api/v1/scan/full")
async def scan_full(request: ScanRequest) -> dict:
    """Starts multiple scans using all WAV tools (Wapiti and Zap) and fingerprinting tools (WhatWeb and SearchVulns) with user-defined configurations"""