import json

def _parse_meta_generator(meta_data: dict, technologies: list):
    for item in meta_data:
        _string = ""
        _version = ""
        for index in range(len(item)):
            if item[index] == ";": # Edge case of Tech_name version; wherein the tech is displayed with features
                break
            if item[index].isdigit() or item[index] == ".":
                _version += item[index]
            elif item[index] != len(item) - 1:
                _string += item[index]
        technologies.append({_string.rstrip(): [_version]})

def _parse_whatweb():
    _excluded = ["UncommonHeaders", "Open-Graph-Protocol", "Title", "Frame", "Script"]
    _trivial = ["Email", "Script", "IP", "Country", "HTTPServer"]
    _versioned_tech = []
    _tech = []
    _cookies = []
    _extra = []
    with open("../temp/whatweb/report.json") as _:
        report = json.load(_)

        for plugin, content in report[0]["plugins"].items():
            if plugin == "MetaGenerator" and len(content) > 0:
                _parse_meta_generator(content["string"], _versioned_tech)
                continue
            if plugin in _excluded:
                continue
            if plugin in _trivial:
                _extra.append({plugin: content["string"]})
                continue
            if plugin == "Cookies": # Handle cookies differently
                _cookies.append({plugin: content["string"]})
                continue
            if content is not None and "version" in content:
                _temp = {plugin: content["version"]}
                if _temp not in _versioned_tech:
                    _versioned_tech.append(_temp)
                continue
            _tech.append({plugin: content})
    return [_versioned_tech, _tech, _cookies, _extra]