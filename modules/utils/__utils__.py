import asyncio
import socket
import uuid
from typing import TYPE_CHECKING

from loguru import logger

from modules.utils.directory_utils import ensure_directory_exists

if TYPE_CHECKING:
    from services.managers.ScannerManager import ScannerManager


def unroll_sarif_rules(sarif_report: dict) -> dict:
    """
    Creates a dictionary from a SARIF reports rules. It assigns the id as the key and the rest of the contents as its values.
    The purpose is to create a table/dictionary that allows for lookups on keys for quicker comparison.
    """
    _returnable = {}
    for rule in sarif_report["runs"][0]["tool"]["driver"]["rules"]:
        _lookup_values = {}
        for key, value in rule.items():
            if key != "id":
                _lookup_values[key] = value
        _returnable[rule["id"]] = _lookup_values
    return _returnable


def critical_counter(sarif_report: dict, rules: dict | list = None) -> int:
    """
    Counts the number of critical vulnerabilities
    """
    count = 0
    if rules is None:
        _rules = unroll_sarif_rules(sarif_report)
    else:
        _rules = rules
    if isinstance(_rules, dict):
        for vulnerability in sarif_report["runs"][0]["results"]:
            _rule = _rules.get(vulnerability["ruleId"])
            if _rule["properties"].get("risk") is None:
                # Wapiti
                if str.lower(vulnerability.get("level", "")) == "error":
                    count += 1
            else:
                if (
                    str.lower(_rule["properties"]["risk"]) == "high"
                    or str.lower(_rule["properties"]["risk"]) == "critical"
                ):
                    count += 1
        return count
    else:
        for scanner in sarif_report:
            for vulnerability in scanner:
                _rule: dict
                for rule in rules:
                    if vulnerability["ruleId"] in rule:
                        _rule = rule.get(vulnerability["ruleId"])
                        break
                if _rule["properties"].get("risk") is None:
                    # Wapiti
                    if str.lower(vulnerability["level"]) == "error":
                        count += 1
                else:
                    if (
                        str.lower(_rule["properties"]["risk"]) == "high"
                        or str.lower(_rule["properties"]["risk"]) == "critical"
                    ):
                        count += 1
        return count


def check_directories():
    """
    Ensures all required directories exist with proper permissions.
    Creates them if they don't exist.
    """
    from modules.utils.load_configs import DEV_ENV

    # List of all directories that need to exist
    directories = [
        DEV_ENV["report_paths"]["wapiti"],
        DEV_ENV["report_paths"]["whatweb"],
        DEV_ENV["report_paths"]["zap"],
        DEV_ENV["report_paths"]["searchVulns"],
        DEV_ENV["report_paths"]["full_scan"],
        DEV_ENV["report_paths"]["exports"],
        "./logs",  # For loguru logs
    ]

    for directory in directories:
        if directory:  # Skip empty strings
            ensure_directory_exists(directory, mode=0o777)
            logger.info(f"Verified directory: {directory}")


def create_required_files_and_directories():
    """
    This function creates required files and directories needed for the app to function.
    However, this function does not take into account any missing API keys from third party services
    """
    pass


def check_url_local_test(url: str) -> str:
    """Check if a url contains localhost or 127.0.0.1 and returns the docker equivalent"""
    if url.__contains__("localhost") or url.__contains__("127.0.0.1"):
        return url.replace("localhost", "host.docker.internal")
    return url


def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("localhost", port))
            return False
        except OSError:
            return True


def generate_random_uuid() -> str:
    return str(uuid.uuid4())


def run_start_scan(instance: "ScannerManager", url: str, session: str, **config):
    """
    Run the async start_scan from ScannerManager in a coroutine.
    """
    return asyncio.run(instance.start_scan(url, session, **config))
