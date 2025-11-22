import json
import os
import time

import aiofiles
import docker

from modules.interfaces.IAsyncScannerAdapter import IAsyncScannerAdapter
from modules.utils.load_configs import DEV_ENV


class WhatWebAdapter(IAsyncScannerAdapter):
    _base_whatweb_path = f"{DEV_ENV['report_paths']['whatweb']}"
    _searchVulns_path = DEV_ENV["report_paths"]["searchVulns"]
    _NO_TECH_MESSAGE = "No technologies found"

    async def start_scan(self, url: str, session: str):
        self._check_files()
        await self._launch_mounted_container(url, session)
        tech_list = self.parse_results(session)
        if tech_list.__contains__("error"):
            return tech_list, {"error": True, "message": self._NO_TECH_MESSAGE}
        elif len(tech_list["data"][0]) > 0 or tech_list["data"][0] is not None:
            return tech_list, self._query_search_vulns(tech_list.get("data")[0], session)
        else:
            return tech_list, {"error": True, "message": self._NO_TECH_MESSAGE}

    def stop_scan(self, scan_id: str | int) -> int:
        """TBD"""
        pass

    async def generate_config(self, user_config: dict) -> dict:
        """TBD"""
        pass

    def parse_results(self, session: str) -> dict:
        _excluded = ["UncommonHeaders", "Open-Graph-Protocol", "Title", "Frame", "Script"]
        _trivial = ["Email", "Script", "IP", "Country", "HTTPServer"]
        _versioned_tech = []
        _tech = []
        _cookies = []
        _extra = []
        with open(f"{self._base_whatweb_path}\\{session}.json", "r+") as _:
            report = json.load(_)
            if len(report) <= 0 or report is None:
                return {"error": True, "message": self._NO_TECH_MESSAGE}
            for plugin, content in report[0]["plugins"].items():
                if plugin == "MetaGenerator" and len(content) > 0:
                    self._parse_meta_generator(content["string"], _versioned_tech)
                    continue
                if plugin in _excluded:
                    continue
                if plugin in _trivial:
                    _extra.append({plugin: content["string"]})
                    continue
                if plugin == "Cookies":  # Handle cookies differently
                    _cookies.append({plugin: content["string"]})
                    continue
                if content is not None and "version" in content:
                    _temp = {plugin: content["version"]}
                    if _temp not in _versioned_tech:
                        _versioned_tech.append(_temp)
                    continue
                _tech.append({plugin: content})
        return {"data": [_versioned_tech, _tech, _cookies, _extra]}

    async def async_parse(self, session: str) -> dict:
        _excluded = ["UncommonHeaders", "Open-Graph-Protocol", "Title", "Frame", "Script"]
        _trivial = ["Email", "Script", "IP", "Country", "HTTPServer"]
        _versioned_tech = []
        _tech = []
        _cookies = []
        _extra = []
        with aiofiles.open(f"{self._base_whatweb_path}\\{session}.json", "r+") as _:
            report = json.load(_)
            if len(report) <= 0 or report is None:
                return {"error": True, "message": self._NO_TECH_MESSAGE}
            for plugin, content in report[0]["plugins"].items():
                if plugin == "MetaGenerator" and len(content) > 0:
                    self._parse_meta_generator(content["string"], _versioned_tech)
                    continue
                if plugin in _excluded:
                    continue
                if plugin in _trivial:
                    _extra.append({plugin: content["string"]})
                    continue
                if plugin == "Cookies":  # Handle cookies differently
                    _cookies.append({plugin: content["string"]})
                    continue
                if content is not None and "version" in content:
                    _temp = {plugin: content["version"]}
                    if _temp not in _versioned_tech:
                        _versioned_tech.append(_temp)
                    continue
                _tech.append({plugin: content})
        return {"data": [_versioned_tech, _tech, _cookies, _extra]}

    @staticmethod
    async def _launch_mounted_container(url: str, session: str):
        """Launches a docker container that utilizes the volume flag to store a whatweb report."""
        client = docker.from_env()
        client.containers.run("iamyourdev/whatweb",
                              ["./whatweb", "--verbose", "--log-json", f"./reports/{session}.json", url],
                              volumes={
                                  DEV_ENV["report_paths"]["whatweb"]: {'bind': '/src/whatweb/reports', 'mode': 'rw'}},
                              auto_remove=True)

    @staticmethod
    def _parse_meta_generator(meta_data: dict, technologies: list):
        for item in meta_data:
            _string = ""
            _version = ""
            for index in range(len(item)):
                if item[index] == ";":  # Edge case of Tech_name version; wherein the tech is displayed with features
                    break
                if item[index].isdigit() or item[index] == ".":
                    _version += item[index]
                elif item[index] != len(item) - 1:
                    _string += item[index]
            technologies.append({_string.rstrip(): [_version]})

    @staticmethod
    def _check_files():
        """Checks to see if a file exists, if not, creates a new file; else, remove the files contents"""
        if not os.path.isdir(DEV_ENV["report_paths"]["whatweb"]):
            os.makedirs(DEV_ENV["report_paths"]["whatweb"])

    def _query_search_vulns(self, technology: list[dict] | str, session: str):
        """
        Queries vulnerabilities found in a fingerprinted technology.
        :param technology: a technology or list of technologies
        :param session: name of the session
        """
        if technology is None or len(technology) == 0:
            return {"error": True, "message": self._NO_TECH_MESSAGE}
        _temp = []
        _commands = ["./search_vulns.py", "-u", "--include-single-version-vulns", "-f", "json", "-o",
                     f"/home/search_vulns/reports/{session}.json"]
        if type(technology) is str:
            _temp.append(f"{technology}")
        else:
            for dictionary in technology:
                for key, value in dictionary.items():
                    if type(value) is list:  # multiple versions detected
                        for version in value:
                            _temp.append(f"{key} {version}")
                    else:
                        _temp.append(f"{key} {value}")
        for query in _temp:
            _commands.append("-q")
            _commands.append(query)

        # Can be changed to a more bash environment where we do docker exec into a running container with the command
        # This can incur less overhead of starting a new container and monitor the health of the running one.
        client = docker.from_env()

        if len(_commands) == 0:  # No fingerprinted technology with versions are found
            return {"error": True, "message": self._NO_TECH_MESSAGE}

        try:
            container = client.containers.run(
                "search_vulns",
                tty=True,
                volumes={f"{self._searchVulns_path}": {"bind": "/home/search_vulns/reports", "mode": "rw"}},
                command=_commands,
                detach=True
            )
            while container.status == "running":
                print("Still querying with search_vulns...")
                time.sleep(2)
            with open(f"{self._searchVulns_path}\\{session}.json", "r") as f:
                queries = json.load(f)
                _returnable = {"found": {}, "not_found": []}
                for key, value in queries.items():
                    if type(value) is list:
                        _returnable["found"][key] = value
                    else:
                        _returnable["not_found"].append({key: "No vulnerabilities found"})
                return _returnable
        except Exception as e:
            print(f"An error occurred: \n {e}")
            return {"error": True, "message": self._NO_TECH_MESSAGE}
