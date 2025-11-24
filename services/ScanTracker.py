import json
import os

import modules.utils.__utils__ as utilities
from modules.interfaces.enums.restack_enums import ScanStep
from modules.utils.load_configs import DEV_ENV

class ScanTracker:
    # OPTIONAL: WHEN DOING ASYNC PLEASE USE ASYNCIO OR AIO
    _ACTIVE_SCAN_PATH = DEV_ENV["templates_path"]["active_scans"]

    def add_scan(self, session:str, target:str, step:ScanStep):
        with open(self._ACTIVE_SCAN_PATH, "r"):
            active_scans = self.check_if_invalid_or_empty()

        with open(self._ACTIVE_SCAN_PATH, "w") as scans:
            active_scans[session] = {
                "session": session,
                "target": target,
                "step": step.value,
            }
            json.dump(active_scans, scans)
        print("Scan was added!")


    def remove_scan(self, session:str):
        with open(self._ACTIVE_SCAN_PATH, "r"):
            active_scans = self.check_if_invalid_or_empty()

        with open(self._ACTIVE_SCAN_PATH, "w") as scans:
            active_scans.pop(session)
            json.dump(active_scans, scans)

    def fetch_scan(self, session:str) -> dict:
        with open(self._ACTIVE_SCAN_PATH, "r"):
            active_scans = self.check_if_invalid_or_empty()
            return active_scans.get(session)

    def fetch_all_scans(self) -> dict:
        with open(self._ACTIVE_SCAN_PATH, "r"):
            active_scans = self.check_if_invalid_or_empty()
            if len(active_scans) == 0:
                return {"message": "There are no scans"}
            return active_scans

    def advance_step(self, session:str, step:ScanStep):
        """
        Changes what step the tracked scan is in.
        """
        with open(self._ACTIVE_SCAN_PATH, "r"):
            active_scans = self.check_if_invalid_or_empty()
            active_scans[session]["step"] = step

    def generate_unique_session(self) -> str:
        with open(self._ACTIVE_SCAN_PATH, "r"):
            active_scans = self.check_if_invalid_or_empty()
            _session = utilities.generate_random_uuid()
            if len(active_scans) == 0:
                return _session
            while _session in active_scans:
                _session = utilities.generate_random_uuid()
            return _session

    def check_if_invalid_or_empty(self) -> dict | None:
        """ Checks if the file in _ACTIVE_SCAN_PATH exists or is valid json. If not, return an empty dict."""
        with open(self._ACTIVE_SCAN_PATH, "r") as scans:
            if os.stat(self._ACTIVE_SCAN_PATH).st_size == 0:
                return {}
            else:
                try:
                    return json.load(scans)
                except json.decoder.JSONDecodeError:
                    return {}