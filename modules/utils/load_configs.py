import json

ENV = json.load(open("./config/ENV.json"))
WAPITI_CONFIG = json.load(open("./config/templates/wapiti_config.json"))
ZAP_TEMPLATE = json.load(open("./config/templates/zap_template.json"))
ZAP_MAPPING = json.load(open("./config/templates/zap_to_wapiti.json"))
