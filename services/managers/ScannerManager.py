import asyncio
import random
import uuid

from loguru import logger

import modules.utils.__utils__ as utilities
from modules.interfaces.enums.restack_enums import ZAPScanType, ScannerType
from modules.scanners.WapitiScanner import WapitiAdapter
from modules.scanners.WhatWebScanner import WhatWebAdapter
from modules.scanners.ZapScanner import ZapScanner


class ScannerManager:
    _active_scans = {}

    @logger.catch
    async def start_scan(self, url: str, session: str, **config):
        """
            Starts a scan. A scan started this way will be run on a background thread.
            This allows for simultaneous scanning to ensure scalability.
            However, compute resources may be easily exhausted when running a lot of docker containers.

            :param url: The url to be scanned.
            :param session: scan identifier.
            :param config: Configuration arguments
                - `scanner_type` (ScannerType): tool to utilize the scan; refer to ScannerType
                - `api_key` (str): api key to be used by zap.
                - `port` (int): port to be used by zap.
                - `user_config`: contains user-defined configurations for scanners.
        """
        # Check which scanner to use
        scanner_type = config.get("scanner_type")
        if scanner_type is None:
            logger.error("{object} does not exist or is null", scanner_type)
            raise ValueError  # Throw no scan type defined error
        elif not isinstance(scanner_type, ScannerType):
            logger.error("{obj} is not of type {type}", scanner_type, type(ScannerType))
            raise TypeError  # Throw invalid scanner type

        # init required objects for scanning ( extra info tools like whatweb, search_vulns, etc.)
        _whatweb_scanner = WhatWebAdapter()

        match scanner_type:
            case ScannerType.ZAP:
                # If the scanner is OWASP ZAP, check what type of scan is requested
                scan_type = config.get("scan_type")
                if scan_type is None:
                    logger.error("{object} does not exist or is null", scan_type)
                    raise ValueError  # Throw no scan type defined error
                elif not isinstance(scan_type, ZAPScanType):
                    logger.error("{obj} is not of type {type}", scan_type, type(ZAPScanType))
                    raise TypeError  # Throw invalid scan type

                # Check if api_key and port is present in config
                logger.info("Checking parameters for a valid zap scan")
                try:
                    if config.get("api_key") is None or type(config.get("api_key")) is not str:
                        logger.warning("An API key was not properly defined, generating a random API key...")
                        config["api_key"] = str(uuid.uuid4())
                    if config.get("port") is None or type(config.get("port")) is not int:
                        logger.warning("A port was not properly defined, looking for an open port to use...")
                        _default_port = 8080
                        while utilities.is_port_in_use(_default_port):
                            logger.warning("Port {port} was already in use, looking for another port...", _default_port)
                            _default_port = random.randint(300, 10000)
                        config["port"] = _default_port
                except Exception:
                    logger.exception(
                        "Something went wrong when checking for valid zap parameters! Please see the log file!")

                logger.info("Starting a whatweb query...")
                _raw_whatweb_results, _query_results = await _whatweb_scanner.start_scan(url, session)

                zap_scan_object = ZapScanner()
                logger.info("Starting a zap scan in the backgroud...")
                _zap_result = zap_scan_object.start_scan(
                    {
                        "scanner_type": scan_type,
                        "api_key": config.get("api_key"),
                        "port": config.get("port"),
                        "session": session,
                        "url": url,
                        "scan_type": config.get("scan_type")
                    }
                )
                return _zap_result, _query_results, _raw_whatweb_results
            case ScannerType.WAPITI:
                wapiti_instance = config.get("wapiti_instance")
                wapiti_config = config.get("wapiti_config")

                if wapiti_instance is None:
                    logger.warning("No wapiti scanner instance detected, creating a new instance...")
                    wapiti_instance = WapitiAdapter()
                if wapiti_config is None:
                    logger.warning("There was no configuration set for wapiti, generating a default configuration...")
                    wapiti_config = wapiti_instance.generate_config({
                        "modules": ["all"]
                    })

                return wapiti_instance.start_scan(
                    {
                        "url": url,
                        "session": session,
                        "wapiti_config": wapiti_config
                    }
                )
            case _:
                # log
                raise ValueError  # There is no valid argumentor match that was passed here

    def _run_start_scan(self, url: str, session: str, **config):
        return asyncio.run(self.start_scan(url, session, **config))

    def poll_running_scans(self, scan_id: str):
        if scan_id is None:
            return {"error": True, "message": "Invalid scan_id"}
        elif type(scan_id) is not str:
            return {"error": True, "message": "scan_id is not of type str"}
        try:
            scan = self._active_scans.get(scan_id)
            if scan is None:
                return {"status": 200, "message": f"Scan with {scan_id} was not found"}
            else:
                return {"status": 200, "message": "success", "data": scan}
        except Exception as e:
            # log
            print(e)  # Something unexpected happened here
            return {"error": True, "message": "Internal Server Error"}

    def generate_unique_session(self) -> str:
        if len(self._active_scans) == 0:
            return utilities.generate_random_uuid()
        _session = utilities.generate_random_uuid()
        while self._active_scans.get(_session):
            _session = utilities.generate_random_uuid()
        return _session

    @staticmethod
    def generate_random_config() -> dict:
        """
        Generates a random configuration for ZAP scans.
        :return: A dict with both api_key and port filled
        """
        _default_port = random.randint(300, 10000)
        while utilities.is_port_in_use(_default_port):
            _default_port = random.randint(300, 10000)
        return {"api_key": str(uuid.uuid4()), "port": _default_port}
