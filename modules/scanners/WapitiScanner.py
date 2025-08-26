import json
import pprint
import subprocess

from modules.interfaces.IScannerAdapter import IScannerAdapter
from modules.utils.load_configs import DEV_ENV
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
        with open(DEV_ENV["templates_path"]["wapiti"], "r") as file: #TODO: check if files exists
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

    def _parse_to_sarif(self, path:str):
        # TODO: Move to parse_results
        # TODO: There are still findings that are not converted in mappings
        sarif_report = {"version": "2.1.0",
                        "runs": [{"tool": {"driver": {"name": "Wapiti3", "rules": []}}, "results": []}]}
        WSTG_TO_CWE = open("../config/templates/wstg_to_cwe.json", "r")
        mapping = json.load(WSTG_TO_CWE)
        with open(path, "r") as report:
            report = json.load(report)

            # Check for definitions and format
            # This could be extracted as a function and be automated as the contents are barely changed
            for category in report["vulnerabilities"]:
                if len(report["vulnerabilities"][category]) != 0:
                    rule = {"id": category}  # id name shortDescription:text fullDescription:text help:text,markdown properties:cwe,owasp_wstg
                    rule.update({"shortDescription": {"text": category}})
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
                                if category in mapping:
                                    _list = []
                                    if type(mapping[category]) is list:
                                        for item in mapping[category]:
                                            _list.append(item)
                                    else:
                                        _list.append(mapping[category])
                                    for wstg in value:
                                        _list.append(wstg)
                                rule.update({"properties": {"tags": _list}})
                    sarif_report["runs"][0]["tool"]["driver"]["rules"].append(rule)

            # Check for vulnerabilities and format
            # This is the only dynamic part of the report
            for category in report["vulnerabilities"]:
                if len(report["vulnerabilities"][category]) != 0:
                    for vulnerability in report["vulnerabilities"][category]:
                        result = {"ruleID": category, "locations": [], "properties": {}}  # ruleID level message:text locations[physicalLocation:artifactLocation:uri] properties:httpRequest,curlCommand,wstg,referer,parameter
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
                                    if key == "wstg":
                                        _list = []
                                        for item in value:
                                            _list.append(item)
                                        result["properties"].update({"wstg": _list})
                                    result["properties"].update({key: value})
                    sarif_report["runs"][0]["results"].append(result)

        #Write report changes
        with open(path, "w") as sarif:
            sarif.write(json.dumps(sarif_report))

        WSTG_TO_CWE.close()