import json
import urllib.parse
from pprint import pprint

redefinitions = json.load(open("../config/templates/zap_to_wapiti.json", "r"))

with open("../temp/zap/20250723_05-58-51.json") as f:
    report = json.load(f)

    #Redifine names so some vulnerabilities have the same definition
    for alert in report:
        for wap_def, zap_def in redefinitions.items():
            if type(zap_def) is dict:
                for definition in zap_def:
                    if alert["name"] == definition:
                        alert["name"] = wap_def
                        continue
            if alert["name"] == zap_def:
                alert["name"] = wap_def

    #TODO: format these fields and write them to database.
    with open("../config/templates/zap_template.json", "r") as template:
        _format = json.load(template) # This object is copied by n. Where n = len(report) | Object should not be copied
        _findings = []
        _critical = 0
        for alert in report:
            _temp = _format
            if alert["risk"] == "Critical":
                _critical += 1
            _temp["name"] = alert["name"]
            _temp["risk"] = alert["risk"]
            _temp["description"] = alert["description"]
            _temp["confidence"] = alert["confidence"]
            _temp["method"] = alert["method"]
            if len(alert["param"]) > 0:
                _temp["param"] = alert["param"]
            else:
                _temp["param"] = "no param"
            _temp["url"] = alert["url"]
            _temp["solution"] = alert["solution"]
            _temp["reference"] = alert["reference"]#TODO: find a way to filter out http(s)://base.domain and only output the endpoint i.e., /checkouts, /payments, etc.
            _temp["endpoint"] = urllib.parse.urlparse(alert["url"]).path
            _findings.append(_temp)
            pprint(_temp)
            print("-----\n") # May add the "tag" value in the future
