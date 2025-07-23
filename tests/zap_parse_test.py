import json
from pprint import pprint

redefinitions = json.load(open("../config/templates/zap_to_wapiti.json", "r"))

with open("../temp/zap/20250721_01-12-21.json") as f:
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
        _format = json.load(template)
    for alert in report:
        print(alert["name"])
        print(alert["risk"])
        print(alert["description"])
        print(alert["confidence"])
        print(alert["method"])
        if len(alert["param"]) > 0:
            print(alert["param"])
        print(alert["url"]) # TODO: find a way to filter out http(s)://base.domain and only output the endpoint i.e., /checkouts, /payments, etc.
        print(alert["solution"])
        print(alert["reference"])
        print("-----\n") # May add the "tag" value in the future
