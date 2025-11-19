import os
import socket
import uuid


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
    print(rules)
    if rules is None:
        _rules = unroll_sarif_rules(sarif_report)
    else:
        _rules = rules
    if isinstance(_rules, dict):
        for vulnerability in sarif_report["runs"][0]["results"]:
            _rule = _rules.get(vulnerability["ruleId"])
            if _rule["properties"].get("risk") is None:
                # Wapiti
                if str.lower(_rule["level"]) == "error":
                    count += 1
            else:
                if str.lower(_rule["properties"]["risk"]) == "high" or str.lower(
                        _rule["properties"]["risk"]) == "critical":
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
                    if str.lower(_rule["properties"]["risk"]) == "high" or str.lower(
                            _rule["properties"]["risk"]) == "critical":
                        count += 1
        return count


def check_directories():
    """This functions should check the existence of several required directories.
    These directories are reports and temp"""
    if not os.path.exists("./reports"):
        os.mkdir("./reports")
    if not os.path.exists("./temp"):
        os.mkdir("./temp")


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