import json

# Excluded in report: Script, UncommonHeaders, Open-Graph-Protocol, Title, Frame

_excluded = ["UncommonHeaders", "Open-Graph-Protocol", "Title", "Frame", "Script"]
_trivial = ["Email", "Script", "IP", "Country", "HTTPServer"]
_versioned_tech = []
_tech = []
_cookies = []
_extra = []

with open("../temp/whatweb/report.json") as report:
    report = json.load(report)

    for plugin, content in report[0]["plugins"].items():
        if plugin in _excluded:
            continue
        if plugin in _trivial:
            _extra.append({plugin: content})
            continue
        if plugin == "Cookies": # Handle cookies differently
            _cookies.append(content)
        if content is not None and "version" in content:
            _versioned_tech.append({plugin: content["version"]})
            continue
        _tech.append({plugin: content})
        # print(f"{plugin}: {content}")

    print(f"Versioned Technologies:\n{_versioned_tech}\n\nTechnologies:\n{_tech}\n\nExtra:\n{_extra}\n\nCookies:\n{_cookies}")