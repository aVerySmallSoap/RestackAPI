import json
import subprocess
from warnings import deprecated

from modules.interfaces.IScannerAdapter import IScannerAdapter
from modules.interfaces.enums.ScanTypes import ScanType
from modules.utils.load_configs import DEV_ENV
from services.builders.WapitiConfigBuilder import WapitiConfigBuilder

class WapitiAdapter(IScannerAdapter):

    # TODO: check if the scan errored in any way
    def start_scan(self, url:str,  scan_type: ScanType, user_config: dict = None):
        """Starts a wapiti scan
        :param scan_type: QUICK or FULL
        :type scan_type: enums.ScanType
        :param url: The url to scan
        :type url: str
        :param user_config: The user configuration
        :type user_config: dict"""
        config_builder = WapitiConfigBuilder()
        match scan_type:
            case ScanType.QUICK:
                _config = config_builder.url(url).output_path(user_config["path"]).build()
                process = subprocess.Popen(_config)
                process.wait()
            case ScanType.FULL:
                # TODO: Add implementation
                pass
            case _:
                pass


    def stop_scan(self, scan_id:str|int) -> int:
        pass

    #TODO: check if files exists
    #TODO: sanitize config commands
    def generate_config(self, user_config: dict) -> dict:
        """Generate a config object from an HTTP request."""
        with open(DEV_ENV["templates_path"]["wapiti"], "r") as file:
            _template = json.load(file)
            if len(user_config) == 0:
                return {"error": True, "message": "Invalid config: Configuration empty!"}
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
        """Parses generated report to SARIF v2.1.0
        :param path: The path of the report to parse
        :type path: str
        :return: The parsed report"""
        sarif_report = {"version": "2.1.0","runs": [{"tool": {"driver": {"name": "Wapiti3", "rules": []}}, "results": []}]}
        with open(path, "r") as report:
            report = json.load(report)
            self._parse_definitions_to_sarif(sarif_report, report)
            for category in report["vulnerabilities"]:
                if len(report["vulnerabilities"][category]) != 0:
                    for vulnerability in report["vulnerabilities"][category]:
                        result = {"ruleId": category, "locations": [], "properties": {}}
                        for key, value in vulnerability.items():
                            match key:
                                case "level":
                                    self._parse_level_to_sarif(value, result)
                                case "info":
                                    result.update({"message": {"text": value}})
                                case "path":
                                    result["locations"].append({"physicalLocation": {"artifactLocation": {"uri": value}}})
                                case _:
                                    if key == "wstg":
                                        result["properties"].update({"wstg": value})
                                    result["properties"].update({key: value})
                    sarif_report["runs"][0]["results"].append(result)
        return sarif_report

    @staticmethod
    def _parse_definitions_to_sarif(sarif_report, report):
        """Parses Wapiti3's vulnerability definitions to sarif. This function has an intended side effect of mutating the rule variable.
        :param sarif_report: dictionary to modify
        :param report: report to read and rewrite"""
        WSTG_TO_CWE = open("config/templates/wstg_to_cwe.json", "r")
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

    @staticmethod
    def _parse_level_to_sarif(level: int, result: dict):
        """Parses Wapiti's level information to sarif. A util function
        :param level:
        :param result: dictionary to modify"""
        if level == 0:
            result.update({"level": "note"})
        elif level == 1:
            result.update({"level": "warning"})
        else:
            result.update({"level": "error"})