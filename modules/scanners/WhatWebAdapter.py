import json
import os

import docker

from modules.interfaces.IAsyncScannerAdapter import IAsyncScannerAdapter
from modules.utils.load_configs import DEV_ENV


class WhatWebAdapter(IAsyncScannerAdapter):

    async def start_scan(self, url:str, config: dict = None):
        self._check_files()
        await self._launch_mounted_container(url, config["session_name"])

    def stop_scan(self, scan_id: str | int) -> int:
        """TBD"""
        pass

    def generate_config(self, user_config: dict) -> dict:
        """TBD"""
        pass

    def parse_results(self, path: str) -> dict:
        #TODO: Make use of session names and session IDs
        _excluded = ["UncommonHeaders", "Open-Graph-Protocol", "Title", "Frame", "Script"]
        _trivial = ["Email", "Script", "IP", "Country", "HTTPServer"]
        _versioned_tech = []
        _tech = []
        _cookies = []
        _extra = []
        with open(path, "r+") as _:
            report = json.load(_)
            print(report)
            if len(report) <= 0 or report is None:
                return {"error":True, "message": "No technologies found"}
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

    async def _launch_mounted_container(self, url: str, session_name: str):
        """Launches a docker container that utilizes the volume flag to store a whatweb report."""
        client = docker.from_env()
        client.containers.run("iamyourdev/whatweb",
                              ["./whatweb", "-a 1", "--verbose", "--log-json", f"./reports/{session_name}.json", url],
                              volumes={
                                  DEV_ENV["report_paths"]["whatweb"]: {'bind': '/src/whatweb/reports', 'mode': 'rw'}},
                              auto_remove=True,
                              name="whatweb")

    def _parse_meta_generator(self, meta_data: dict, technologies: list):
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

    def _check_files(self):
        """Checks to see if a file exists, if not, creates a new file; else, remove the files contents"""
        if not os.path.isdir(DEV_ENV["report_paths"]["whatweb"]):
            os.makedirs(DEV_ENV["report_paths"]["whatweb"])