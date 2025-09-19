import json
import urllib.parse

with open("../temp/zap/zap_test.json", "r") as f:
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
    with open("zap_report_v2.json", "w") as out:
        json.dump(_sarif, out, indent=2)



    # _sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "OWASP ZAP", "rules": []}}, "results": []}]}
    # _temp_rules = []
    # _temp_results = []
    # for alert in report: # Build rules
    #     _rule = {}
    #     _properties = {}
    #     _rule.update({"id": alert["pluginId"]})
    #     _rule.update({"name": alert["name"]})
    #     _rule.update({"fullDescription": {"text": alert["description"]}})
    #     # references
    #     _markdown = {"markdown": {}}
    #     for ref, link in alert["tags"].items():
    #         if link != "" or link is not None:
    #             _markdown.update({"markdown": {ref: link}})
    #     _rule.update({"help": {"text": alert["solution"], "markdown": _markdown}})
    #
    #     #properties
    #     _properties.update({"cwe": alert["cweid"]})
    #     _properties.update({"wasc": alert["wascid"]})
    #     _properties.update({"risk": alert["risk"]})
    #     _rule.update({"properties": _properties})
    #     _temp_rules.append(_rule)
    # _sarif["runs"][0]["tool"]["driver"].update({"rules": _temp_rules})
    #
    # for alert in report: #Build results
    #     _result = {}
    #     _properties = {}
    #
    #     _result.update({"ruleId": alert["pluginId"]})
    #     _result.update({"message": {"text": alert["description"]}})
    #     _result.update({"locations": [{"physicalLocation": {"artifactLocation": {"uri": alert["url"]}}}]})
    #     match alert["risk"]:
    #         case "High":
    #             _result["level"] = "error"
    #         case "Informational":
    #             _result["level"] = "note"
    #         case "Low":
    #             _result["level"] = "note"
    #         case "Medium":
    #             _result["level"] = "warning"
    #         case _:
    #             _result["level"] = "none"
    #
    #     #properties
    #     if alert["other"] != "" or alert["other"] is not None:
    #         _properties.update({"other": alert["other"]})
    #     _properties.update({"method": alert["method"]})
    #     _properties.update({"evidence": alert["evidence"]})
    #     _properties.update({"confidence": alert["confidence"]})
    #     _result.update({"properties": _properties})
    #     _temp_results.append(_result)
    # _sarif["runs"][0]["tool"]["driver"].update({"results": _temp_results})


