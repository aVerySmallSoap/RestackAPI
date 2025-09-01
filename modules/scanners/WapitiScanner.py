import json
import subprocess
from warnings import deprecated

from modules.interfaces.IScannerAdapter import IScannerAdapter
from modules.utils.load_configs import DEV_ENV
from services.builders.WapitiConfigBuilder import WapitiConfigBuilder

class WapitiAdapter(IScannerAdapter):

    # TODO: check if the scan errored in any way
    # TODO: identify if the scan type is QUICK, FULL or CUSTOM using ScanTypes.py
    def start_scan(self, url:str, config: dict = None):
        config_builder = WapitiConfigBuilder()
        config = config_builder.url(url).output_path(config["path"]).build()
        process = subprocess.Popen(config)
        process.wait()

    def stop_scan(self, scan_id:str|int) -> int:
        pass

    #TODO: check if files exists
    #TODO: sanitize config commands
    def generate_config(self, user_config: dict) -> dict:
        """Generate a config object from an HTTP request."""
        with open(DEV_ENV["templates_path"]["wapiti"], "r") as file:
            _template = json.load(file)
            if len(user_config) == 0:
                return {"error": "Invalid config: Configuration empty!"}
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

    @deprecated("This method is deprecated, use _parse_to_sarif instead")
    def parse_results(self, path:str) -> dict:
        """Converts Wapiti results into a custom format"""
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

    # TODO: There are still findings that are not converted in mappings
    # TODO: move to parse_results()
    def _parse_to_sarif(self, path:str):
        sarif_report = {"version": "2.1.0","runs": [{"tool": {"driver": {"name": "Wapiti3", "rules": []}}, "results": []}]}
        with open(path, "r") as report:
            report = json.load(report)
            self._parse_definitions_to_sarif(sarif_report, report)
            for category in report["vulnerabilities"]:
                if len(report["vulnerabilities"][category]) != 0:
                    for vulnerability in report["vulnerabilities"][category]:
                        result = {"ruleID": category, "locations": [], "properties": {}}
                        for key, value in vulnerability.items():
                            match key:
                                case "level":
                                    if value == 0:
                                        result.update({"level": "note"})
                                    elif value == 1:
                                        result.update({"level": "warning"})
                                    else:
                                        result.update({"level": "error"})
                                case "info":
                                    result.update({"message": {"text": value}})
                                case "path":
                                    result["locations"].append({"physicalLocation": {"artifactLocation": {"uri": value}}})
                                case _:
                                    if key == "wstg": # This _list is just the contents of value, can just copy contents for better readability
                                        _list = []
                                        for item in value:
                                            _list.append(item)
                                        result["properties"].update({"wstg": _list})
                                    result["properties"].update({key: value})
                    sarif_report["runs"][0]["results"].append(result)
        with open(path, "w") as sarif:
            sarif.write(json.dumps(sarif_report))

    @staticmethod
    def _parse_definitions_to_sarif(sarif_report, report):
        """Parses Wapiti3's vulnerability definitions to sarif. This function has an intended side effect of mutating the rule variable.
        :param sarif_report: dictionary to modify
        :param report: report to read"""
        WSTG_TO_CWE = open("../../config/templates/wstg_to_cwe.json", "r")
        mapping = json.load(WSTG_TO_CWE)
        for category in report["vulnerabilities"]:
            rule = {"id": category, "shortDescription": {"text": category}}
            for key, value in report["classifications"][category].items():
                match key:
                    case "desc":
                        rule.update({"fullDescription": value})
                    case "sol":
                        rule.update({"help": {"text": value}})
                    case "ref":
                        markdown = "References:\n"
                        for title, link in value.items():
                            markdown.join(f"\n[{title}]({link})")
                        rule["help"].update({"markdown": value})
                    case "wstg":
                        _list = []
                        if category in mapping:
                            _list.append(mapping[category])
                            for wstg in value:
                                _list.append(wstg)
                        rule.update({"properties": {"tags": _list}})
            sarif_report["runs"][0]["tool"]["driver"]["rules"].append(rule)
        WSTG_TO_CWE.close()

    @staticmethod
    def _parse_info_to_sarif(sarif_report, report):
        """TBD"""
        pass