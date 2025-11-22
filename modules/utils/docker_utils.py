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
    client = docker.from_env()
    if not os.path.exists(f"{_zap_path}\\{config['session_name']}"):
        os.mkdir(f"{_zap_path}\\{config['session_name']}")
    return client.containers.run(
        "zaproxy/zap-stable",
        ["zap.sh", "-daemon", "-Xmx8g", "-host", "0.0.0.0", "-port", f"{config['port']}", "-dir",
         f"/tmp/{config['session_name']}", "-config",
         "api.addrs.addr.name=.*", "-config", "api.addrs.addr.regex=true", "-config", f"api.key={config["apikey"]}"],
        volumes={f"{_zap_path}\\{config['session_name']}": {"bind": f"/tmp/{config['session_name']}", "mode": "rw"}},
        # TODO: Change path to ENV
        ports={f"{config['port']}/tcp": config["port"]},
        detach=True
    )
