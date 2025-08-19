import json
import subprocess

from modules.interfaces.IScannerAdapter import IScannerAdapter
from modules.utils.load_configs import ENV
from services.builders.WapitiConfigBuilder import WapitiConfigBuilder

class WapitiAdapter(IScannerAdapter):
    def start_scan(self, url:str, config: dict = None):
        configBuilder = WapitiConfigBuilder()
        config = configBuilder.url(url).output_path(config["path"]).build()
        process = subprocess.Popen(config)
        process.wait() #TODO: check if the scan errored in any way
        #TODO: identify if the scan type is QUICK, FULL or CUSTOM using ScanTypes.py

    def stop_scan(self, scan_id:str|int) -> int:
        pass

    def generate_config(self, user_config: dict) -> dict:
        """Generate a config object from an HTTP request."""
        with open(ENV["templates_path"]["wapiti"], "r") as file: #TODO: check if files exists
            _template = json.load(file)
            if len(user_config) == 0:
                return {"error": "Invalid config: Configuration empty!"}
            else:
                #TODO: check if config has valid inputs, else throw an error
                pass
            for key, value in user_config.items():
                match key:
                    case "url":
                        _template["url"] = value
                    case "modules":
                        _template["modules"] = value
                    case "path":
                        _template["path"] = value
                    case "scan_type":
                        _template["scan_type"] = value
                    case "scan_time":
                        _template["scan_time"] = value
                    case "concurrent_tasks":
                        _template["concurrent_tasks"] = value
                    case "is_overridden":
                        _template["is_overridden"] = value
                    case "custom_args":
                        _template["custom_args"] = value
            return _template

    def parse_results(self, path:str) -> dict:
        with open(path, "r") as report:
            wapiti_report = json.load(report)
            categories, descriptions, vulnerabilities = [], [], []
            _critical = 0
            for category in wapiti_report["vulnerabilities"]: # Fetch categories that only have vulnerabilities and retrieve their description and mitigations
                if len(wapiti_report["vulnerabilities"][category]) != 0:
                    categories.append(category)
            for category, data in wapiti_report["classifications"].items(): # Get description of each category
                if category in categories:
                    descriptions.append(data)
            for category in categories: # Get vulnerabilities
                _arr = []
                for vulnerability in wapiti_report["vulnerabilities"][category]:
                    vulnerability.update({"name": category})
                    for key, value in vulnerability.items():
                        if key == "level":
                            match value:
                                case 1:
                                    value = "Low"
                                case 2:
                                    value = "Medium"
                                case 3:
                                    value = "High"
                                case 4:
                                    _critical += 1
                                    value = "Critical"
                        vulnerability.update({key: value})
                    _arr.append(vulnerability)
                vulnerabilities.append(_arr)
            return {"parsed":{"categories": categories, "descriptions": descriptions, "vulnerabilities": vulnerabilities}, "vulnerability_count": len(vulnerabilities),"critical_vulnerabilities": _critical, "raw": wapiti_report, "extra": wapiti_report["infos"]}