
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

def critical_counter(sarif_report: dict) -> int:
    """
    Counts the number of critical vulnerabilities
    """
    count = 0
    _rules = unroll_sarif_rules(sarif_report)
    for vulnerability in sarif_report["runs"][0]["results"]:
        _rule = _rules.get(vulnerability["ruleId"])
        if str.lower(_rule["properties"]["risk"]) == "high" or str.lower(_rule["properties"]["risk"]) == "critical":
            count += 1
    return count