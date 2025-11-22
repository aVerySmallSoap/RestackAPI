import json
import shutil
import time
from urllib import parse as url_parser

import requests
from loguru import logger
from zapv2 import ZAPv2

import modules.utils.docker_utils as docker_utilities
from modules.interfaces.IScannerAdapter import IScannerAdapter
from modules.interfaces.enums.restack_enums import ZAPScanType
from modules.utils.load_configs import DEV_ENV


class ZapScanner(IScannerAdapter):
    _base_zap_path = f"{DEV_ENV['report_paths']['zap']}"
    _timeout = 300

    @logger.catch
    def start_scan(self, config: dict, **kwargs):
        zap: ZAPv2
        logger.info("Spawning a new container in docker...")
        container = docker_utilities.start_automatic_zap_service(
            {
                "port": config.get("port"),
                "apikey": config.get("api_key"),
                "session_name": config.get("session")
            }
        )
        _start_time = time.time()
        while time.time() - _start_time < self._timeout:
            logger.debug("Sending a request to ZAP...")
            try:
                response = requests.get(f"http://localhost:{config.get('port')}/JSON/core/view/version/",
                                        params={"apikey": config.get("api_key")}, timeout=30)
                if response.status_code == 200:
                    logger.info("Zap API was found and is ready! Version {version}", response.json().get("version"))
                    break
            except requests.exceptions.ConnectionError:
                logger.debug("Zap API is not responding, we will try again...")
                time.sleep(30)
            except Exception as e:
                # print(type(e)) # ConnectionError
                logger.error("We could not find the Zap API")
                break
        logger.debug("Trying to run a scan now")

        if config.get("zap_instance") is None:
            # Try to recreate zap
            zap = ZAPv2(
                apikey=config.get("api_key"),
                proxies={
                    "http": f"127.0.0.1:{config.get('port')}",
                    "https": f"127.0.0.1:{config.get('port')}",
                }
            )
        else:
            zap = config.get("zap_instance")

        try:
            match config["scan_type"]:
                case ZAPScanType.PASSIVE:
                    logger.debug("Starting a passive scan run...")
                    self.start_passive_scan(
                        zap,
                        api_key=config.get("api_key"),
                        port=config.get("port"),
                        session=config.get("session"),
                        url=config.get("url")
                    )
                case ZAPScanType.ACTIVE:
                    logger.debug("Starting an active scan run...")
                    self.start_active_scan(
                        zap,
                        api_key=config.get("api_key"),
                        port=config.get("port"),
                        session=config.get("session"),
                        url=config.get("url")
                    )
                case ZAPScanType.FULL:
                    logger.debug("Starting a full scan run...")
                    self.start_passive_scan(
                        zap,
                        api_key=config.get("api_key"),
                        port=config.get("port"),
                        session=config.get("session"),
                        url=config.get("url")
                    )
                    self.start_active_scan(
                        zap,
                        api_key=config.get("api_key"),
                        port=config.get("port"),
                        session=config.get("session"),
                        url=config.get("url")
                    )
                case _:
                    # log
                    raise TypeError  # There is no valid argumentor match that was passed here
            _returnable = self.parse_results(zap_instance=zap, session=config.get("session"))
            logger.info("Zap scan completed successfully.")
            logger.debug("Cleaning up containers and associated directories...")
            container.stop()
            container.remove()
            shutil.rmtree(f"{self._base_zap_path}\\{config.get('session')}")
            return _returnable
        except TypeError as type_e:
            # log
            print(f"The passed object is not of type {type(ZAPScanType)}\n{type_e}")
        except Exception as e:
            # log
            print(f"Unexpected behavior\n{e}")

    @logger.catch
    def stop_scan(self, session: str):
        """
        Stop the scan directly and interfere with the container
        """
        pass

    @logger.catch
    def parse_results(self, **config) -> dict:
        logger.info(f"Parsing results for {config.get('session')}")
        try:
            _har_alerts = self._fetch_header_and_request_alerts(config.get("zap_instance"),
                                                                session=config.get("session"))
            with open(f"{self._base_zap_path}\\{config.get('session')}.json", "r") as f:
                report = json.load(f)
                _sarif = {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {
                                "driver": {
                                    "name": "OWASP ZAP",
                                    "rules": []
                                }
                            },
                            "results": []
                        }
                    ]
                }
                rules_seen = set()
                for alert in report:
                    if alert.get("pluginId") not in rules_seen:
                        _rule = {
                            "id": alert.get("pluginId"),
                            "name": alert.get("name"),
                            "fullDescription": {"text": alert.get("description")},
                            "help": {
                                "text": alert.get("solution"),
                                "markdown": "\n".join(
                                    f"[{ref}]({link})" for ref, link in alert.get("tags").items() if link != ""
                                )
                            },
                            "properties": {
                                "cwe": alert.get("cweid"),
                                "wasc": alert.get("wascid"),
                                "risk": alert.get("risk")
                            }
                        }
                        _sarif["runs"][0]["tool"]["driver"]["rules"].append(_rule)
                        rules_seen.add(alert.get("pluginId"))

                    # Fetch hars also
                    _alert_har = _har_alerts.get(alert.get("sourceMessageId"))
                    if _alert_har is None:
                        _alert_har = _har_alerts.get(alert.get("id"))
                    _result = {
                        "ruleId": alert.get("pluginId"),
                        "message": {"text": alert.get("pluginId")},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": url_parser.urlparse(alert.get("pluginId")).path}
                                }
                            }
                        ],
                        "properties": {
                            "method": alert.get("method"),
                            "evidence": alert.get("evidence"),
                            "confidence": alert.get("confidence"),
                            "har": _alert_har.pop(0) if _alert_har is not None else None,
                            "zapId": alert.get("id")
                        }
                    }
                    if alert.get("other"):
                        _result["properties"]["other"] = alert.get("other")
                    match alert.get("risk"):
                        case "High":
                            _result["level"] = "error"
                        case "Informational":
                            _result["level"] = "note"
                        case "Low":
                            _result["level"] = "note"
                        case "Medium":
                            _result["level"] = "warning"
                        case _:
                            _result["level"] = "none"
                    _sarif["runs"][0]["results"].append(_result)
                logger.info("Parsing finished!")
                return _sarif
        except Exception:
            # log
            pass
        return {}

    @logger.catch
    def start_passive_scan(self, zap: ZAPv2, **config):
        self._context_lookup(zap, url=config.get("url"))
        logger.info("Starting a zap scan in the passive mode...")
        try:
            while int(zap.pscan.records_to_scan) > 0:
                time.sleep(2)

            with open(f"{self._base_zap_path}\\{config.get('session')}.json", "w") as file:
                file.write(
                    json.dumps(
                        zap.core.alerts(baseurl=config.get("url"))
                    )
                )
                file.flush()
                file.close()
        except Exception:
            # log
            pass

    @logger.catch
    def start_active_scan(self, zap: ZAPv2, **config):
        self._context_lookup(zap, url=config.get("url"))
        try:
            scan_id = zap.ascan.scan(config.get("url"), recurse=True)
            while int(zap.ascan.status(scan_id)) < 100:
                # log
                time.sleep(2)
            with open(f"{self._base_zap_path}\\{config.get('session')}.json", "w") as file:
                file.write(json.dumps(zap.core.alerts(baseurl=config.get("url"))))
                file.flush()
                file.close()
        except Exception:
            # log
            pass

    @staticmethod
    @logger.catch
    def _context_lookup(zap: ZAPv2, **config):
        logger.info("Starting a context lookup")
        try:
            # Start of context lookup
            zap.core.access_url(config.get("url"), followredirects=True)

            # Crawling
            # Traditional Spider
            try:
                # Configuration
                zap.spider.set_option_parse_robots_txt(True)
                zap.spider.set_option_parse_robots_txt(True)

                # Scanning
                scan_id = zap.spider.scan(url=config.get("url"), recurse=True)
                time.sleep(5)
                while int(zap.spider.status(scan_id)) < 100:
                    print(f"Traditional spider crawling @ {int(zap.spider.status(scan_id))}%")
                    time.sleep(5)

                # Additional context (future feature for seeding more URLs)
            except Exception:
                # log
                pass  # Unexpected behavior or HTTPConnection error

            # Ajax Spider
            try:
                # Configuration
                zap.ajaxSpider.set_option_enable_extensions(True)
                zap.ajaxSpider.set_option_max_crawl_depth(0)
                zap.ajaxSpider.set_option_reload_wait(10)

                # Scanning
                zap.ajaxSpider.scan(config.get("url"))
                time.sleep(5)
                while zap.ajaxSpider.status == "running":
                    print(f"Ajax spider crawling and is currently: {zap.ajaxSpider.status}")
                    time.sleep(5)
            except Exception:
                # log
                pass  # Unexpected behavior or HTTPConnection error

            # Client Spider (Experimental)
            try:
                headers = {
                    "Accept": "application/json",
                    "X-ZAP-API-Key": config.get("api_key"),
                }
                base = f"http://localhost:{config.get('port')}/JSON"
                scan_id = requests.get(f"{base}/clientSpider/action/scan",
                                       params={"url": config.get("url"), "pageLoadTime": "30"}, headers=headers).json()[
                    'scan']
                time.sleep(2)
                while int(requests.get(f'{base}/clientSpider/view/status', params={'scanId': scan_id},
                                       headers=headers).json()['status']) < 100:
                    time.sleep(2)
            except Exception:
                # log
                pass  # Unexpected behaviour or HTTPConnection error

        except Exception:
            # log
            pass  # unexpected behavior

    @logger.catch
    def _fetch_header_and_request_alerts(self, zap: ZAPv2, **config) -> dict:
        logger.info("Fetching headers and request alerts...")
        with open(f"{self._base_zap_path}\\{config.get('session')}.json", "r") as f:
            report = json.load(f)
            message_ids: str = ""
            for alert in report:
                message_ids += str(alert.get("sourceMessageId")) + ","
            message_ids.removesuffix(",")  # remove trailing comma
            try:
                messages = zap.core.messages_by_id(message_ids)
                _returnable: dict
                if len(messages) > 0 and type(messages) is not str:
                    _har_list: list
                    for message in messages:
                        har = {
                            "id": message.get("id"),
                            "requestBody": message.get("requestBody"),
                            "requestHeader": message.get("requestHeader"),
                            "responseBody": message.get("responseBody"),
                            "responseHeader": message.get("responseHeader")
                        }
                        _har_list.append(har)
                    for har in _har_list:
                        if len(_returnable) == 0 or har.get("id") not in _returnable:
                            _returnable[har.get("id")] = har
                        else:
                            _returnable.get(har.get("id")).append(har)
                return _returnable
            except Exception:
                # log
                pass
        return {}
