import json
import subprocess

from modules.interfaces.IScannerAdapter import IScannerAdapter
from services.builders.WapitiConfigBuilder import WapitiConfigBuilder

class WapitiAdapter(IScannerAdapter):
    def start_scan(self, config: dict):
        configBuilder = WapitiConfigBuilder() # this should be put into generate_config
        config = configBuilder.url(config["url"]).output_path(config["path"]).build()
        process = subprocess.Popen(config)
        process.wait()

    def stop_scan(self, scan_id:str|int) -> int:
        pass

    def generate_config(self, user_config: dict) -> dict:
        pass

    def parse_results(self, path:str) -> dict:
        with open(path, "r") as report:
            wapiti_report = json.load(report)
            categories = []
            descriptions = []
            vulnerabilities = []
            # Fetch categories that only have vulnerabilities and retrieve their description and mitigations
            for category in wapiti_report["vulnerabilities"]:
                if len(wapiti_report["vulnerabilities"][category]) != 0:
                    categories.append(category)
            # Get description of each category
            for category, data in wapiti_report["classifications"].items():
                if category in categories:
                    descriptions.append(data)
            # Get vulnerabilities
            for category in categories:
                _arr = []
                for vulnerability in wapiti_report["vulnerabilities"][category]:
                    for key, value in vulnerability.items():  # Normalize levels into CVE standard format
                        if key == "level":
                            match value:
                                case 1:
                                    value = "Low"
                                case 2:
                                    value = "Medium"
                                case 3:
                                    value = "High"
                                case 4:
                                    value = "Critical"
                        vulnerability.update({key: value})
                    _arr.append(vulnerability)
                vulnerabilities.append(_arr)
            return {"categories": categories, "descriptions": descriptions, "vulnerabilities": vulnerabilities}