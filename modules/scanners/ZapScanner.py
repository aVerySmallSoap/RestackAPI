import json
import time
import urllib.parse
from copy import deepcopy

from modules.interfaces.IScannerAdapter import IScannerAdapter
from modules.interfaces.enums.ZAPScanTypes import ZAPScanTypes
from zapv2 import ZAPv2

class ZapAdapter(IScannerAdapter):
    #TODO: implement passive scanning
    #TODO: implement auto scanning
    #TODO: implement active scanning
    _redefinitions = json.load(open("./config/templates/zap_to_wapiti.json", "r"))
    _template = json.load(open("./config/templates/zap_template.json", "r"))
    zap: ZAPv2

    def __init__(self, config: dict):
        self.zap = ZAPv2(apikey=config["apikey"])

    def start_scan(self, url:str, config: dict):
        self._context_lookup(url)
        if config["scan_type"] == ZAPScanTypes.PASSIVE:
            self._start_passive_scan(url, config["path"])
        elif config["scan_type"] == ZAPScanTypes.ACTIVE:
            self._start_active_scan(url, config["path"])

    def stop_scan(self, scan_id: str | int) -> int:
        pass

    def generate_config(self, user_config: dict) -> dict:
        pass

    def parse_results(self, path:str) -> dict:
        #TODO: No error handling
        with open(path, "r") as report:
            zap_report = json.load(report)

            # Redefine names so some vulnerabilities have the same definition
            for alert in zap_report:
                for wap_def, zap_def in self._redefinitions.items():
                    if type(zap_def) is dict:
                        for definition in zap_def:
                            if alert["name"] == definition:
                                alert["name"] = wap_def
                                continue
                    if alert["name"] == zap_def:
                        alert["name"] = wap_def
            _findings = []
            _critical = 0
            for alert in zap_report:
                _temp = deepcopy(self._template)
                if alert["risk"] == "Critical":
                    _critical += 1
                _temp["name"] = alert["name"]
                _temp["risk"] = alert["risk"]
                _temp["description"] = alert["description"]
                _temp["confidence"] = alert["confidence"]
                _temp["method"] = alert["method"]
                if len(alert["param"]) > 0:
                    _temp["param"] = alert["param"]
                else:
                    _temp["param"] = "no param"
                _temp["url"] = alert["url"]
                _temp["solution"] = alert["solution"]
                _temp["reference"] = alert[
                    "reference"]
                _temp["endpoint"] = urllib.parse.urlparse(alert["url"]).path
                _findings.append(_temp)
        #TODO: get _context_lookup to find crawled pages and remove the constant value
        return {"parsed": _findings, "crawled_pages": 1, "vulnerability_count": len(zap_report), "critical_vulnerabilities": _critical, "raw": zap_report}

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