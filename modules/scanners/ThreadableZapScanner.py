import asyncio
import json
import time
from urllib import parse as url_parser

import aiofiles
import requests
from zapv2 import ZAPv2

from modules.interfaces.IThreadableScannerAdapter import IThreadableScannerAdapter
from modules.interfaces.enums.restack_enums import ZAPScanType
from modules.utils.load_configs import DEV_ENV
from loguru import logger


class ThreadableZapScanner(IThreadableScannerAdapter):
    _base_zap_path = f"{DEV_ENV['report_paths']['zap']}"

    @logger.catch
    async def start_scan(self, config: dict, **kwargs):
        """
        Spawns a thread and starts a ZAP scan.
        """
        zap:ZAPv2
        scan_object = kwargs.get('threadable_instance')
        if scan_object is None:
            scan_object = ThreadableZapScanner()
        elif not isinstance(scan_object, ThreadableZapScanner):
            scan_object = ThreadableZapScanner()
            # log | Recreate this object into the right object

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
                    await asyncio.to_thread(
                        scan_object.start_passive_scan,
                        zap,
                        api_key=config.get("api_key"),
                        port=config.get("port"),
                        session= config.get("session")
                    )
                case ZAPScanType.ACTIVE:
                    await asyncio.to_thread(
                        scan_object.start_active_scan,
                        zap,
                        api_key=config.get("api_key"),
                        port=config.get("port"),
                        session=config.get("session")
                    )
                case _:
                    # log
                    raise TypeError  # There is no valid argumentor match that was passed here
        except TypeError as type_e:
            #log
            print(f"The passed object is not of type {type(ZAPScanType)}\n{type_e}")
        except Exception as e:
            #log
            print(f"Unexpected behavior\n{e}")

    @logger.catch
    def stop_scan(self, session: str):
        """
        Stop the scan directly and interfere with the container
        """
        pass

    @logger.catch
    async def parse_results(self, config: dict) -> dict:
        try:
            _har_alerts = await self._fetch_header_and_request_alerts(config.get("zap_instance"))
            with aiofiles.open(f"{self._base_zap_path}\\{config.get('session')}.json", "r") as f:
                report = json.loads(f)
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
                return _sarif
        except Exception:
            #log
            pass
        return {}

    @logger.catch
    async def start_passive_scan(self, zap: ZAPv2, **config):
        await self._context_lookup(zap, config)

        try:
            while int(zap.pscan.records_to_scan) > 0:
                time.sleep(2)

            with aiofiles.open(f"{self._base_zap_path}\\{config.get('session')}.json", "w") as file:
                file.write(
                    json.dumps(
                        zap.core.alerts(baseurl=config.get("url"))
                    )
                )
                file.flush()
                file.close()
        except Exception:
            #log
            pass

    @logger.catch
    async def start_active_scan(self, zap: ZAPv2, **config):
        await self._context_lookup(zap, config)

        try:
            scan_id = zap.ascan.scan(config.get("url"), recurse=True)
            while int(zap.ascan.status(scan_id)) < 100:
                #log
                time.sleep(2)
            with aiofiles.open(f"{self._base_zap_path}\\{config.get('session')}.json", "w") as file:
                file.write(json.dumps(zap.core.alerts(baseurl=config.get("url"))))
                file.flush()
                file.close()
        except Exception:
            #log
            pass

    @staticmethod
    @logger.catch
    async def _context_lookup(zap: ZAPv2, **config):
        try:
            # Start of context lookup
            zap.core.access_url(config.get("url"), followredirects=True)

            # Crawling
            # Traditional Spider
            try:
                # Configuration
                zap.spider.set_option_parse_robots_txt(True)
                zap.spider.set_option_parse_robots_txt(True)

                #Scanning
                scan_id = zap.spider.scan(url=config.get("url"), recurse=True)
                time.sleep(5)
                while int(zap.spider.status(scan_id)) < 100:
                    print(f"Traditional spider crawling @ {int(zap.spider.status(scan_id))}%")
                    time.sleep(5)

                #Additional context (future feature for seeding more URLs)
            except Exception as e:
                #log
                pass # Unexpected behavior or HTTPConnection error

            # Ajax Spider
            try:
                # Configuration
                zap.ajaxSpider.set_option_enable_extensions(True)
                zap.ajaxSpider.set_option_max_crawl_depth(0)
                zap.ajaxSpider.set_option_reload_wait(10)

                #Scanning
                zap.ajaxSpider.scan(config.get("url"))
                time.sleep(5)
                while zap.ajaxSpider.status == "running":
                    print(f"Ajax spider crawling and is currently: {zap.ajaxSpider.status}")
                    time.sleep(5)
            except Exception as e:
                #log
                pass # Unexpected behavior or HTTPConnection error

            # Client Spider (Experimental)
            try:
                headers = {
                    "Accept": "application/json",
                    "X-ZAP-API-Key": config.get("api_key"),
                    }
                base = f"http://localhost:{config.get('port')}/JSON"
                scan_id = requests.get(f"{base}/clientSpider/action/scan", params={"url": config.get("url"), "pageLoadTime": "30"}, headers=headers).json()['scan']
                time.sleep(2)
                while int(requests.get(f'{base}/clientSpider/view/status', params={'scanId': scan_id}, headers=headers).json()['status']) < 100:
                    time.sleep(2)
            except Exception as e:
                #log
                pass # Unexpected behaviour or HTTPConnection error

        except Exception as e:
            #log
            pass # unexpected behavior

    @staticmethod
    @logger.catch
    async def _fetch_header_and_request_alerts(zap: ZAPv2, **config) -> dict:
        with aiofiles.open(config.get("path"), "r") as f:
            report = json.loads(f)
            message_ids:str
            for alert in report:
                message_ids += str(alert.get("sourceMessageId")) + ","
            message_ids.removesuffix(",") # remove trailing comma
            try:
                messages = zap.core.messages_by_id(message_ids)
                _returnable: dict
                if len(messages) > 0 and type(messages) is not str:
                    _har_list:list
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
                #log
                pass
        return {}