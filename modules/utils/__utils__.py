
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

def critical_counter(sarif_report: dict, rules: dict|list = None) -> int:
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