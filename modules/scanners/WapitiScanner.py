import json
import subprocess

from loguru import logger

from modules.interfaces.IScannerAdapter import IScannerAdapter
from modules.utils.load_configs import DEV_ENV
from services.builders.WapitiConfigBuilder import WapitiConfigBuilder


class WapitiAdapter(IScannerAdapter):
    _wapiti_base_path = DEV_ENV["report_paths"]["wapiti"]

    def start_scan(self, config: dict, **kwargs):
        """Starts a wapiti scan
        :param config:
        """
        config_builder = WapitiConfigBuilder()
        _config = config_builder.url(config.get("url")).modules(config.get("modules")).output_path(
            config.get("session")).build()
        process = subprocess.Popen(_config, creationflags=(subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW))
        process.wait()
        return self.parse_results(config.get("session"))

    def stop_scan(self, scan_id: str | int) -> int:
        pass

    # TODO: check if files exists
    # TODO: sanitize config commands
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

    def parse_results(self, session: str) -> dict:
        """Parses generated report to SARIF v2.1.0
        :param session: The path of the report to parse
        :type session: str
        :return: The parsed report"""
        logger.debug("Parsing Wapiti report...")
        sarif_report = {"version": "2.1.0",
                        "runs": [{"tool": {"driver": {"name": "Wapiti3", "rules": []}}, "results": []}]}
        with open(f"{self._wapiti_base_path}\\{session}.json", "r") as report:
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
                                    result["locations"].append(
                                        {"physicalLocation": {"artifactLocation": {"uri": value}}})
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
        with open("templates/wstg_to_cwe.json", "r") as file:
            mapping = json.load(file)
            for category in report["vulnerabilities"]:
                rule = {"id": category, "shortDescription": {"text": category}}
                for key, value in report["classifications"][category].items():
                    match key:
                        case "desc":
                            rule.update({"fullDescription": {"text": value}})
                        case "sol":
                            rule.update({"help": {"text": value}})
                        case "ref":
                            markdown = "References:\n"
                            for title, link in value.items():
                                markdown.join("\n[{}]({})".format(title, link))
                            rule["help"].update({"markdown": value})
                        case "wstg":
                            _list = []
                            if category in mapping:
                                _list.append(mapping[category])
                                for wstg in value:
                                    _list.append(wstg)
                            rule.update({"properties": {"tags": _list}})
                sarif_report["runs"][0]["tool"]["driver"]["rules"].append(rule)

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

    @staticmethod
    def start_automatic_scan(url: str, user_config: dict = None):
        config_builder = WapitiConfigBuilder()
        _config = config_builder.url(url).output_path(user_config["path"]).build()
        process = subprocess.Popen(_config, creationflags=(subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW))
        process.wait()
