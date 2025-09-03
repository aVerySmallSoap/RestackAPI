import json

def parse_search_vulns_result(path:str) -> list:
    """Parse the results of search_vulns tool.
    :param path: The path of the file to parse
    :return: A list of dictionaries"""
    with open(path, "r") as file:
        report = json.load(file)
        _list = []
        for technology, content in report.items():
            if isinstance(content, str):
                continue
            else:
                _tech = {"tech": technology, "vulns": []}
                _temp = []
                for cve_details in content["vulns"].values():
                    _vuln = {}
                    _vuln.update({"id": cve_details['id']})
                    _vuln.update({"sources": cve_details['match_sources']})
                    _vuln.update({"description": cve_details['description']})
                    _vuln.update({"published": cve_details['published']})
                    _vuln.update({"modified": cve_details['modified']})
                    _vuln.update({"cvss_ver": cve_details['cvss_ver']})
                    _vuln.update({"cvss": cve_details['cvss']})
                    _vuln.update({"exploits": cve_details['exploits']})
                    _vuln.update({"aliases": cve_details['aliases']})
                    _temp.append(_vuln)
                _tech.update({"vulns": _temp})
                _list.append(_tech)
    return _list