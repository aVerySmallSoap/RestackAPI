import json
import time
import urllib.parse

from modules.interfaces.IScannerAdapter import IScannerAdapter
from modules.interfaces.enums.restack_enums import ZAPScanType
from zapv2 import ZAPv2

from modules.interfaces.types.RetryExceeded import RetryExceeded
from modules.utils.docker_utils import start_automatic_zap_service


class ZapAdapter(IScannerAdapter):
    zap: ZAPv2

    def __init__(self, config: dict):
        self.zap = ZAPv2(apikey=config["apikey"], proxies={"http": "127.0.0.1:8080"})

    def start_scan(self, url:str, config: dict):
        if config["scan_type"] == ZAPScanType.PASSIVE:
            self._context_lookup(url, api_key=config["apikey"])
            self._start_passive_scan(url, config["path"])
        elif config["scan_type"] == ZAPScanType.ACTIVE:
            self._context_lookup(url, api_key=config["apikey"])
            self._start_active_scan(url, config["path"])
        elif config["scan_type"] == ZAPScanType.AUTOMATIC:
            self._start_automatic_scan(url, config, config["client_instance"])

    def stop_scan(self, scan_id: str | int) -> int:
        """TBD"""
        pass

    def generate_config(self, user_config: dict) -> dict:
        """TBD"""
        pass

    # TODO: No error handling
    def parse_results(self, path:str, zap: ZAPv2 = None) -> dict:
        if zap is None:
            zap = self.zap
        _alert_hars = self._fetch_alert_har(path, zap)
        with open(path, "r") as f:
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
            rules_seen = set()  # avoid duplicate rules
            for alert in report:
                if alert["pluginId"] not in rules_seen:
                    _rule = {
                        "id": alert["pluginId"],
                        "name": alert["name"],
                        "fullDescription": {"text": alert["description"]},
                        "help": {
                            "text": alert["solution"],
                            "markdown": "\n".join(
                                f"[{ref}]({link})" for ref, link in alert["tags"].items() if link != ""
                            )
                        },
                        "properties": {
                            "cwe": alert["cweid"],
                            "wasc": alert["wascid"],
                            "risk": alert["risk"]
                        }
                    }
                    _sarif["runs"][0]["tool"]["driver"]["rules"].append(_rule)
                    rules_seen.add(alert["pluginId"])
            for alert in report:
                _alert_har = _alert_hars.get(alert.get("sourceMessageId"))
                if _alert_har is None:
                    _alert_har = _alert_hars.get(alert["id"])
                _result = {
                    "ruleId": alert["pluginId"],
                    "message": {"text": alert["description"]},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": urllib.parse.urlparse(alert["url"]).path}
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
                    _result["properties"]["other"] = alert["other"]
                match alert["risk"]:
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

    @staticmethod
    def _fetch_alert_har(path:str, zap: ZAPv2) -> dict:
        with open(path, 'r') as f:
            report = json.load(f)
            message_ids = ""
            for alert in report:
                message_ids += str(alert['sourceMessageId']) + ','
            message_ids = message_ids.removesuffix(',')
            messages = zap.core.messages_by_id(message_ids)
            _returnable = {}
            if len(messages) > 0 and type(messages) is not str:
                _har_list = []
                for message in messages:  # id requestBody requestHeader responseBody responseHeader
                    har = {
                        "id": message["id"],
                        "requestBody": message["requestBody"],
                        "requestHeader": message["requestHeader"],
                        "responseBody": message["responseBody"],
                        "responseHeader": message["responseHeader"]
                    }
                    _har_list.append(har)
                for har in _har_list:
                    if len(_returnable) == 0 or har["id"] not in _returnable:
                        _returnable[har["id"]] = [har]
                    else:
                        _returnable.get(har["id"]).append(har)  # Assumes that the type returned is a list
                with open('./test.json', 'w') as test:
                    test.write(json.dumps(_returnable))
            return _returnable

    def _context_lookup(self, target: str, api_key:str, additional_context: list = None, zap_instance: ZAPv2 = None) -> bool:
        zap = zap_instance if zap_instance is not None else self.zap
        zap.core.access_url(url=target, followredirects=True)
        if additional_context is not None:
            for context in additional_context:
                zap.core.access_url(url=context, followredirects=True)

        # Traditional Crawler
        scanId = zap.spider.scan(url=target, recurse=True)
        zap.spider.set_option_parse_robots_txt(True)
        zap.spider.set_option_parse_sitemap_xml(True)
        time.sleep(5)
        while int(zap.spider.status(scanId)) < 100:
            print(f"Crawling with traditional crawler @ {int(self.zap.spider.status(scanId))}")
            time.sleep(2)
        if additional_context is not None and len(additional_context) > 0:
            for context in additional_context:
                access_scanId = self.zap.spider.scan(url=context, recurse=True)
                time.sleep(5)
                while int(self.zap.spider.status(access_scanId)) < 100:
                    time.sleep(2)

        # Ajax Crawler
        self.zap.ajaxSpider.scan(target)
        self.zap.ajaxSpider.set_option_enable_extensions(True)
        self.zap.ajaxSpider.set_option_max_crawl_depth(0)
        self.zap.ajaxSpider.set_option_reload_wait(10)
        time.sleep(5)
        while self.zap.ajaxSpider.status == "running":
            print(f"Crawling with ajax crawler @ {self.zap.ajaxSpider.status}")
            time.sleep(2)
        if additional_context is not None and len(additional_context) > 0:
            for context in additional_context:
                self.zap.ajaxSpider.scan(url=context)
                time.sleep(5)
                while self.zap.ajaxSpider.status == "running":
                    time.sleep(2)

        # Client Spider
        # zapv2.clientSpider is for version 4.1+! The only available and latest version is 4.0
        # try:
        #     headers = {
        #         'Accept': 'application/json',
        #         'X-ZAP-API-Key': api_key,
        #     }
        #     base = 'http://localhost:8080/JSON'
        #     scanId = requests.get(f'{base}/clientSpider/action/scan', params={'url': target, 'pageLoadTime': "30"}, headers=headers).json()['scan']
        #     time.sleep(2)
        #     while int(requests.get(f'{base}/clientSpider/view/status', params={'scanId': scanId}, headers=headers).json()['status']) < 100:
        #         time.sleep(2)
        #     if additional_context is not None and len(additional_context) > 0:
        #         for context in additional_context:
        #             access_scanId = requests.get(f'{self.zap.base}/clientSpider/action/scan', params={'url': context}, headers=headers).json()['scan']
        #             while int(requests.get(f'{self.zap.base}/clientSpider/view/status', params={'scanId': access_scanId}, headers=headers).json()['status']) < 100:
        #                 time.sleep(2)
        # except Exception as e:
        #     print(f"Client Spider could not crawl the site!\n{e}")
        return True

    def _start_passive_scan(self, target: str, report_path: str):
        while int(self.zap.pscan.records_to_scan) > 0:
            time.sleep(2)

        with open(report_path, "w") as file:
            file.write(json.dumps(self.zap.core.alerts(baseurl=target)))
            file.flush()

    def _start_active_scan(self, target: str, report_path: str):
        scanID = self.zap.ascan.scan(target, recurse=True)
        while int(self.zap.ascan.status(scanID)) < 100: # TODO: This might error when a scanID does not exist. Maybe due to docker missing the commands or ZAP API not running or ZAP not receiving requests correctly
            time.sleep(2)
        with open(report_path, "w") as file:
            file.write(json.dumps(self.zap.core.alerts(baseurl=target)))
            file.flush()

    def _start_automatic_scan(self, target, config: dict, zap: ZAPv2):
        container = start_automatic_zap_service(config)
        # auto_zap.base = f"http://127.0.0.1:{config['port']}/JSON/"
        _retryExceeded = False
        _retryCount = 0
        while True:
            time.sleep(25)
            try:
                _retryCount += 1
                if _retryExceeded:
                    print("Could not communicate with ZAP API")
                    break
                if _retryCount > 10:
                    print(RetryExceeded())
                    raise RetryExceeded()
                request = zap.stats.stats()
                print(f"Zap API live! Zap version: {request}")
                break
            except Exception as e:
                print(type(e))
                if isinstance(e, RetryExceeded):
                    print(f"Max retries exceeded!")
                    _retryExceeded = True
                print(f"Zap API is still not up! We will try again... @ attempt #{_retryCount} \n{e}\n")

                print(_retryCount)
        self._context_lookup(target, api_key=config["apikey"], zap_instance=zap)
        scanID = zap.ascan.scan(target, recurse=True)
        while int(zap.ascan.status(
                scanID)) < 100:  # TODO: This might error when a scanID does not exist. Maybe due to docker missing the commands or ZAP API not running or ZAP not receiving requests correctly
            time.sleep(2)
        with open(config["path"], "w") as file:
            file.write(json.dumps(self.zap.core.alerts(baseurl=target)))
            file.flush()
        container.stop()
        container.remove()