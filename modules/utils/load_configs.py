import json

ENV = json.load(open("./config/ENV.json", "r"))
WAPITI_CONFIG = json.load(open("./config/templates/wapiti_config.json", "r"))
ZAP_TEMPLATE = json.load(open("./config/templates/zap_template.json", "r"))
ZAP_MAPPING = json.load(open("./config/templates/zap_to_wapiti.json", "r"))
