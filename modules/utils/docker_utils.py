import os
import time

import docker
from docker.models.containers import Container
from zapv2 import ZAPv2

from modules.utils.load_configs import DEV_ENV

# == Report paths ==
_wapiti_path = DEV_ENV["report_paths"]["wapiti"]
_whatweb_path = DEV_ENV["report_paths"]["whatweb"]
_zap_path = DEV_ENV["report_paths"]["zap"]
_full_scan_path = DEV_ENV["report_paths"]["full_scan"]
_searchVulns_path = DEV_ENV["report_paths"]["searchVulns"]


def update_zap_service():
    # This function should always assume that zap is running. This will only run on start-up
    client = docker.from_env()
    containers = client.containers.list(all=True)
    print("Updating zap service")
    for container in containers:
        if container.name == "zap" and container.status == "running":
            try:
                time.sleep(20)  # Wait for the service to warmup and start
                zap = ZAPv2(apikey="test", proxies={"http": "http://127.0.0.1:8080"})
                zap.autoupdate.download_latest_release()
            except Exception as e:
                print(f"We waited for 30 seconds but got: \n {e}")


def start_automatic_zap_service(config: dict) -> Container:
    """
    PERFORMANCE: Maximum speed ZAP configuration for testing
    """
    client = docker.from_env()
    session_path = os.path.join(_zap_path, config["session_name"])
    if not os.path.exists(session_path):
        os.mkdir(session_path)

    return client.containers.run(
        "zaproxy/zap-stable",
        [
            "zap.sh",
            "-daemon",
            "-Xmx6g",
            "-host", "0.0.0.0",
            "-port", f"{config['port']}",
            "-dir", f"/tmp/{config['session_name']}",

            # API Configuration
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
            "-config", f"api.key={config['apikey']}",

            # PERFORMANCE: Disable all checks/updates
            "-config", "start.checkAddonUpdates=false",
            "-config", "start.checkForUpdates=false",

            # PERFORMANCE: Maximum speed spider settings
            "-config", "spider.maxDuration=3",  # 3 min max (fast)
            "-config", "spider.maxDepth=2",  # Shallow depth
            "-config", "spider.threadCount=12",  # Max threads
            "-config", "spider.parseRobotsTxt=false",  # Ignore robots.txt
            "-config", "spider.parseComments=false",  # Skip comment parsing
            "-config", "spider.parseSVGImages=false",  # Skip SVG
            "-config", "spider.parseSitemapXml=false",  # Skip sitemap
            "-config", "spider.postForm=false",  # Skip form posts

            # PERFORMANCE: Disable AJAX spider (slow)
            "-config", "ajaxSpider.enabled=false",

            # PERFORMANCE: Maximum active scan threads
            "-config", "scanner.threadPerHost=12",  # Max threads per host
            "-config", "scanner.hostPerScan=4",  # Scan 4 hosts concurrently
            "-config", "scanner.delayInMs=0",  # No delay between requests

            # PERFORMANCE: Fast timeouts
            "-config", "connection.timeoutInSecs=15",  # Fast timeout
            "-config", "connection.dnsTtlSuccessfulQueries=3600",

            # PERFORMANCE: Disable slow features
            "-config", "view.mode=attack",  # Skip safe mode
            "-config", "database.compact=false",  # Skip DB compaction
            "-config", "stats.enabled=false",  # Disable stats collection

            # PERFORMANCE: Passive scan optimization
            "-config", "pscans.maxAlertsPerRule=10",  # Limit alerts per rule
        ],
        volumes={
            session_path: {
                "bind": f"/tmp/{config['session_name']}",
                "mode": "rw"
            }
        },
        ports={f"{config['port']}/tcp": config["port"]},
        name=f"{config['session_name']}",
        detach=True,
        # PERFORMANCE: Max resources
        mem_limit="6g",
        cpu_quota=400000,  # 4 CPU cores
    )