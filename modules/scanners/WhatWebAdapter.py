import json
import os

import docker

from modules.interfaces.IAsyncScannerAdapter import IAsyncScannerAdapter
from modules.utils.load_configs import DEV_ENV


class WhatWebAdapter(IAsyncScannerAdapter):
    _local_report_path = "./temp/whatweb/report.json"

    async def start_scan(self, url:str, config: dict = None):
        self._check_files()
        await self.discover_then_volume(url)

    def stop_scan(self, scan_id: str | int) -> int:
        pass

    def generate_config(self, user_config: dict) -> dict:
        pass

    def parse_results(self, path: str = None) -> dict:
        raw = self.fetch_plugins_data()
        parsed = self.parse_volume_data()
        return {"raw": raw, "parsed": parsed}

    async def discover_then_volume(self, url: str):
        """Launches a docker container that utilizes the volume flag to store a whatweb report."""
        client = docker.from_env()
        client.containers.run("iamyourdev/whatweb",
                              ["./whatweb", "-a 1", "--verbose", "--log-json=./reports/report.json", url],
                              volumes={
                                  DEV_ENV["report_paths"]["whatweb"]: {'bind': '/src/whatweb/reports', 'mode': 'rw'}},
                              auto_remove=True,
                              name="whatweb")

    def parse_volume_data(self):
        with open(self._local_report_path, "r") as f:
            data = json.load(f)
            if len(data) > 0:
                data = data[0]
                plugins = []
                for key, value in data["plugins"].items():
                    plugins.append({key: value})
                return plugins
            return data

    def fetch_plugins_data(self) -> list:
        with open(self._local_report_path, "r") as f:
            data = json.load(f)
            if len(data) > 0:
                return data[0]
        return data

    def _check_files(self):
        """Checks to see if a file exists, if not, creates a new file; else, remove the files contents"""
        if not os.path.isfile(self._local_report_path):
            open(self._local_report_path, "x").close()
        elif os.path.getsize(self._local_report_path) > 0:
            open(self._local_report_path, "w").close()