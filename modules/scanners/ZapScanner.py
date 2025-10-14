import json
import time
import urllib.parse

from modules.interfaces.IScannerAdapter import IScannerAdapter
from modules.interfaces.enums.ZAPScanTypes import ZAPScanTypes
from zapv2 import ZAPv2

class ZapAdapter(IScannerAdapter):
    #TODO: Improve scanning capabilities
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
        """TBD"""
        pass

    def generate_config(self, user_config: dict) -> dict:
        """TBD"""
        pass

    # TODO: No error handling
    def parse_results(self, path:str) -> dict:
        with open(path, "r") as f:
            report = json.load(f)
            _sarif = {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "OWASP ZAP",
                                "rules": []
                            }
                        },
                        "results": []
                    }
                ]
            }
            rules_seen = set()  # avoid duplicate rules
            for alert in report:
                if alert["pluginId"] not in rules_seen:
                    _rule = {
                        "id": alert["pluginId"],
                        "name": alert["name"],
                        "fullDescription": {"text": alert["description"]},
                        "help": {
                            "text": alert["solution"],
                            "markdown": "\n".join(
                                f"[{ref}]({link})" for ref, link in alert["tags"].items() if link != ""
                            )
                        },
                        "properties": {
                            "cwe": alert["cweid"],
                            "wasc": alert["wascid"],
                            "risk": alert["risk"]
                        }
                    }
                    _sarif["runs"][0]["tool"]["driver"]["rules"].append(_rule)
                    rules_seen.add(alert["pluginId"])
            for alert in report:
                _result = {
                    "ruleId": alert["pluginId"],
                    "message": {"text": alert["description"]},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": urllib.parse.urlparse(alert["url"]).path}
                            }
                        }
                    ],
                    "properties": {
                        "method": alert.get("method"),
                        "evidence": alert.get("evidence"),
                        "confidence": alert.get("confidence")
                    }
                }
                if alert.get("other"):
                    _result["properties"]["other"] = alert["other"]
                match alert["risk"]:
                    case "High":
                        _result["level"] = "error"
                    case "Informational":
                        _result["level"] = "note"
                    case "Low":
                        _result["level"] = "note"
                    case "Medium":
                        _result["level"] = "warning"
                    case _:
                        _result["level"] = "none"
                _sarif["runs"][0]["results"].append(_result)
            # with open("zap_report.sarif", "w") as out:
            #     json.dump(_sarif, out, indent=2)

    def _context_lookup(self, target: str) -> bool:
        # Using both traditional and ajax spider
        scanID = self.zap.spider.scan(target, recurse=True)
        while int(self.zap.spider.status(scanID)) < 100:
            time.sleep(2)

        self.zap.ajaxSpider.scan(target, inscope=False)
        while self.zap.ajaxSpider.status == "running":
            time.sleep(2)
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