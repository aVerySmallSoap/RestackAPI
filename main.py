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

# TODO: Check if reports folder is present in CWD
# NOTE! THIS SHOULD BE DEVELOPED WITH SPECIALIZATION IN MIND. THIS APP SHOULD NOT BE GENERALIZED TO SPEED UP DEVELOPMENT
# CONSIDERATIONS ARE TO LIMIT SCANS TO ORGANIZATION SPECIFIC WEBSITES SUCH AS http://www.mywebsite.com or https://my.personal.site

@app.post("/api/v1/wapiti/scan/quick")
async def wapiti_scan(request: ScanRequest) -> dict:
    _wapiti_scanner = WapitiAdapter()
    _whatweb_scanner = WhatWebAdapter()
    # == testing code ==
    _URL = check_url_local_test(str(request.url))
    # == testing end ==
    time_start = time.perf_counter()
    _scan_start = datetime.now()
    _scannerEngine.enqueue_session(ScannerTypes.WAPITI, _scan_start)
    path = _scannerEngine.generate_file(ScannerTypes.WAPITI)
    config = _wapiti_scanner.generate_config({"path": path, "modules": ["all"]})
    _wapiti_scanner.start_scan(_URL, ScanType.QUICK, config)
    report = _wapiti_scanner.parse_to_sarif(path)  # TODO: Change how the DB reads this
    await _whatweb_scanner.start_scan(_URL)
    _whatweb_results = _whatweb_scanner.parse_results()
    time_end = time.perf_counter()
    scan_time = time_end - time_start
    # _db.insert_wapiti_quick_report(_scan_start, path, _whatweb_results["raw"], report, scan_time) # Rewrite reading of report variable
    if not _whatweb_results.__contains__("error"):
        return {"data": report, "plugins": _whatweb_results["data"], "scan_time": scan_time}
    else:
        return {"data": report, "plugins": _whatweb_results, "scan_time": scan_time}


@app.post("/api/v1/wapiti/scan/full")
async def wapiti_scan_full(request: ScanRequest) -> dict:
    pass


@app.post("/api/v1/zap/scan/passive")
async def zap_passive_scan(request: ScanRequest) -> dict:
    time_start = time.perf_counter()
    _zap_scanner = ZapAdapter({"apikey": "test"})
    _whatweb_scanner = WhatWebAdapter()
    # == testing code ==
    _URL = check_url_local_test(str(request.url))
    # == testing end ==
    _scan_start = datetime.now()
    _scannerEngine.enqueue_session(ScannerTypes.ZAP, _scan_start)
    path = _scannerEngine.generate_file(ScannerTypes.ZAP)
    await _whatweb_scanner.start_scan(_URL)
    _zap_scanner.start_scan(_URL, {"path": path, "scan_type": ZAPScanTypes.PASSIVE, "apikey": "test"})
    _whatweb_results = _whatweb_scanner.parse_results()
    report = _zap_scanner.parse_results(path)
    time_end = time.perf_counter()
    scan_time = time_end - time_start
    if not _whatweb_results.__contains__("error"):
        _db.insert_zap_report(_scan_start, path, _whatweb_results["data"], report, scan_time, _URL)
        return {"data": report, "plugins": _whatweb_results["data"], "scan_time": scan_time}
    else:
        _db.insert_zap_report(_scan_start, path, _whatweb_results, report, scan_time, _URL)
        return {"data": report, "plugins": _whatweb_results, "scan_time": scan_time}


@app.post("/api/v1/zap/scan/active")
async def zap_active_scan(request: ScanRequest) -> dict:
    time_start = time.perf_counter()
    _zap_scanner = ZapAdapter({"apikey": "test"})
    _whatweb_scanner = WhatWebAdapter()
    # == testing code ==
    _URL = check_url_local_test(str(request.url))
    # == testing end ==
    _scan_start = datetime.now()
    _scannerEngine.enqueue_session(ScannerTypes.ZAP, _scan_start)
    path = _scannerEngine.generate_file(ScannerTypes.ZAP)
    await _whatweb_scanner.start_scan(_URL)
    _zap_scanner.start_scan(_URL, {"path": path, "scan_type": ZAPScanTypes.ACTIVE, "apikey": "test"})
    _whatweb_results = _whatweb_scanner.parse_results()
    report = _zap_scanner.parse_results(path)
    time_end = time.perf_counter()
    scan_time = time_end - time_start
    if not _whatweb_results.__contains__("error"):
        _db.insert_zap_report(_scan_start, path, _whatweb_results["data"], report, scan_time, _URL)
        return {"data": report, "plugins": _whatweb_results["data"], "scan_time": scan_time}
    else:
        _db.insert_zap_report(_scan_start, path, _whatweb_results["data"], report, scan_time, _URL)
        return {"data": report, "plugins": _whatweb_results, "scan_time": scan_time}