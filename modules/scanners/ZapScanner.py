import json
import time

from modules.interfaces.IScannerAdapter import IScannerAdapter
from modules.interfaces.enums.ZAPScanTypes import ZAPScanTypes
from zapv2 import ZAPv2

class ZapAdapter(IScannerAdapter):
    #TODO: implement passive scanning
    #TODO: implement auto scanning
    #TODO: implement active scanning
    zap: ZAPv2

    def __init__(self, config: dict):
        self.zap = ZAPv2(apikey=config["apikey"])

    def start_scan(self, config: dict):
        self._context_lookup(config["url"])
        if config["scan_type"] == ZAPScanTypes.PASSIVE:
            self._start_passive_scan(config["url"], config["path"])
        elif config["scan_type"] == ZAPScanTypes.ACTIVE:
            self._start_active_scan(config["url"], config["path"])

    def stop_scan(self, scan_id: str | int) -> int:
        pass

    def generate_config(self, user_config: dict) -> dict:
        pass

    def parse_results(self, path:str) -> dict:
        with open(path, "r") as report:
            zap_report = json.load(report)
            return {"parsed": {}, "raw": zap_report}

    def _context_lookup(self, target: str) -> bool:
        # Using both traditional and ajax spider
        scanID = self.zap.spider.scan(target, recurse=True)
        while int(self.zap.spider.status(scanID)) < 100:
            time.sleep(2)

        self.zap.ajaxSpider.scan(target, inscope=False)
        while self.zap.ajaxSpider.status == "running":
            time.sleep(2)
        #TODO: return false if something fails here
        return True

    def _start_passive_scan(self, target: str, report_path: str):
        while int(self.zap.pscan.records_to_scan) > 0:
            time.sleep(2)

        with open(report_path, "w") as file:
            file.write(json.dumps(self.zap.core.alerts(baseurl=target)))
            file.flush()

    def _start_active_scan(self, target: str, report_path: str):
        scanID = self.zap.ascan.scan(target, recurse=True)
        while int(self.zap.ascan.status(scanID)) < 100:
            time.sleep(2)
        with open(report_path, "w") as file:
            file.write(json.dumps(self.zap.core.alerts(baseurl=target)))
            file.flush()