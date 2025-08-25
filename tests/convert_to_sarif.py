# This file converts vulnerability reports from DAST tools to the SARIF format
# SARIF v2.1.0
import json
from pprint import pprint


# The following function only supports built-in tools and has no

def convert_to_sarif(report: dict):
    """Converts a supported tool's report into a SARIF report format.
    For custom tools and plugins refer to IScannerAdapter's parse_results function."""
    #TODO: How do we navigate different reports?
    #TODO: Move function into each implementation of IScannerAdapter's parse_results
    pass


def _parse_to_sarif(path: str):
    # TODO: Move to parse_results
    # TODO: There are still findings that are not converted
    sarif_report = {"version": "2.1.0",
                    "runs": [{"tool": {"driver": {"name": "Wapiti3", "rules": []}}, "results": []}]}
    WSTG_TO_CWE = open("../config/templates/wstg_to_cwe.json", "r")
    mapping = json.load(WSTG_TO_CWE)
    with open(path, "r") as report:
        report = json.load(report)
        for category in report["vulnerabilities"]:
            if len(report["vulnerabilities"][category]) != 0:
                rule = {}  # id name shortDescription:text fullDescription:text help:text,markdown properties:cwe,owasp_wstg
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
    WSTG_TO_CWE.close()

_parse_to_sarif("D:/Coding_Projects/Python/RestackAPI/reports/wapiti_test.json") # BUG: Not reading full path