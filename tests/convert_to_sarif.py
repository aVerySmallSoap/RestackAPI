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

#Temp
def _parse_to_sarif():
    # TODO: Move to parse_results
    # TODO: There are still findings that are not converted
    sarif_report = {"version": "2.1.0",
                    "runs": [{"tool": {"driver": {"name": "Wapiti3", "rules": []}}, "results": []}]}
    WSTG_TO_CWE = open("../config/templates/wstg_to_cwe.json", "r")
    mapping = json.load(WSTG_TO_CWE)
    with open("../reports/wapiti_test.json", "r") as report:
        report = json.load(report)

        # Check for definitions and format
        # This could be extracted as a function and be automated as the contents are barely changed
        for category in report["vulnerabilities"]:
            if len(report["vulnerabilities"][category]) != 0:
                rule = {
                    "id": category}  # id name shortDescription:text fullDescription:text help:text,markdown properties:cwe,owasp_wstg
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
                    result = {"ruleID": category, "locations": [],
                              "properties": {}}  # ruleID level message:text locations[physicalLocation:artifactLocation:uri] properties:httpRequest,curlCommand,wstg,referer,parameter
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

    with open("../reports/sarif_test.json", "w") as sarif:
        sarif.write(json.dumps(sarif_report))

_parse_to_sarif()