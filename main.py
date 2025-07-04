from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from modules.managers.report_manager import ReportManager
from modules.parsers.wapiti_parser import parse as wapiti_parse
from modules.scanners.wapiti_scan import scan as scan_wapiti

report_manager = ReportManager()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], #TODO: Fetch security certs and allow only a single origin
    allow_methods=["*"],
)

@app.get("/api/v1/wapiti/scan")
async def wapiti_scan(url: str):
    report_manager.generate(datetime.now().strftime("%Y%m%d_%I-%M-%S"))
    path = report_manager.build()
    scan_wapiti(url, path)
    parsed = wapiti_parse(path)
    return parsed

@app.get("/api/v1/wapiti/report/{report_id}")
async def wapiti_report(report_id: str):
    pass

@app.get("/api/v1/whatweb/scan")
async def whatweb_scan(url: str):
    pass

if __name__ == '__main__':
    pass