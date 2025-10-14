import json
import os

script_dir = os.path.dirname(os.path.abspath(__file__))

config_dir = os.path.normpath(os.path.join(script_dir, "..", "..", "config"))
templates_dir = os.path.normpath(os.path.join(script_dir, "..", "..", "templates"))

try:
    DEV_ENV = json.load(open(os.path.join(config_dir, "ENV.json"), "r"))
    DEV_WAPITI_CONFIG = json.load(
        open(os.path.join(templates_dir, "wapiti_config.json"), "r")
    )
    DEV_ZAP_TEMPLATE = json.load(
        open(os.path.join(templates_dir, "zap_template.json"), "r")
    )
except FileNotFoundError as e:
    print("Error: A required configuration file was not found.")
    print(f"Missing file: {e}")
    DEV_ENV, DEV_WAPITI_CONFIG, DEV_ZAP_TEMPLATE, DEV_ZAP_MAPPING = (
        None,
        None,
        None,
        None,
    )
    exit()
