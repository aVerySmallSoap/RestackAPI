import asyncio
import random
import uuid

from loguru import logger

from modules.interfaces.enums.restack_enums import ZAPScanType, ScannerType
from modules.scanners.ThreadableWapitiScanner import ThreadableWapitiScanner
from modules.scanners.ThreadableZapScanner import ThreadableZapScanner
from modules.utils.__utils__ import is_port_in_use, generate_random_uuid


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
            raise() # Throw no scan type defined error
        elif not isinstance(scanner_type, ScannerType):
            logger.error("{obj} is not of type {type}", scanner_type, type(ScannerType))
            raise() # Throw invalid scanner type

        match scanner_type:
            case ScannerType.ZAP:
                # If the scanner is OWASP ZAP, check what type of scan is requested
                scan_type = config.get("scan_type")
                if scan_type is None:
                    logger.error("{object} does not exist or is null", scan_type)
                    raise ()  # Throw no scan type defined error
                elif not isinstance(scan_type, ZAPScanType):
                    logger.error("{obj} is not of type {type}", scan_type, type(ZAPScanType))
                    raise ()  # Throw invalid scan type

                # Check if api_key and port is present in config
                logger.info("Checking parameters for a valid zap scan")
                try:
                    if config.get("api_key") is None or type(config.get("api_key")) is not str:
                        logger.warning("An API key was not properly defined, generating a random API key...")
                        config["api_key"] = str(uuid.uuid4())
                    if config.get("port") is None or type(config.get("port")) is not int:
                        logger.warning("A port was not properly defined, looking for an open port to use...")
                        _default_port = 8080
                        while is_port_in_use(_default_port):
                            logger.warning("Port {port} was already in use, looking for another port...", _default_port)
                            _default_port = random.randint(300, 10000)
                except Exception:
                    logger.exception("Something went wrong when checking for valid zap parameters! Please see the log file!")

                zap_scan_object = ThreadableZapScanner()
                await asyncio.to_thread(
                    zap_scan_object.start_scan,
                    {
                        "scanner_type": scan_type,
                        "api_key": config.get("api_key"),
                        "port": config.get("port"),
                        "session": config.get("session"),
                        "threadable_instance": zap_scan_object
                    }
                )

            case ScannerType.WAPITI:
                wapiti_scan_object = ThreadableWapitiScanner()
                await asyncio.to_thread(
                    wapiti_scan_object.start_scan
                )
            case ScannerType.FULL:
                pass
            case _:
                # log
                raise() # There is no valid argumentor match that was passed here

    async def poll_running_scans(self, scan_id: str):
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
            #log
            print(e) # Something unexpected happened here
            return {"error": True, "message": "Internal Server Error"}

    def generate_unique_session(self) -> str:
        if len(self._active_scans) == 0:
            return generate_random_uuid()
        _session = generate_random_uuid()
        while self._active_scans.get(_session):
            _session = generate_random_uuid()
        return _session
