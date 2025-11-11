import json
import time

import docker
from zapv2 import ZAPv2

from modules.utils.load_configs import DEV_ENV


def start_manual_zap_service(config: dict):
    client = docker.from_env()
    containers = client.containers.list(all=True)
    for container in containers:
        if container.name == "zap" and container.status != "running":
            print("Residual ZAP container found! Cleaning up...")
            container.remove(force=True)
        elif container.name == "zap" and container.status == "running":
            return
    print("Starting ZAP service...")
    client.containers.run("zaproxy/zap-stable",
                        ["zap.sh", "-daemon", "-Xmx12g", "-host", "0.0.0.0", "-config", "api.addrs.addr.name=.*", "-config","api.addrs.addr.regex=true", "-config", f"api.key={config["apikey"]}"],
                              name="zap",
                              volumes={"D:\\Coding_Projects\\Python\\RestackAPI\\temp\\zap": {"bind": "/home/zap","mode": "rw"}}, #TODO: Change path to ENV
                              ports={"8080/tcp": 8080},
                              detach=True)

def update_zap_service():
    # This function should always assume that zap is running. This will only run on start-up
    client = docker.from_env()
    containers = client.containers.list(all=True)
    print("Updating zap service")
    for container in containers:
        if container.name == "zap" and container.status == "running":
            try:
                time.sleep(20) # Wait for the service to warmup and start
                zap = ZAPv2(apikey="test", proxies={"http": "http://127.0.0.1:8080"})
                zap.autoupdate.download_latest_release()
            except Exception as e:
                print(f"We waited for 30 seconds but got: \n {e}")

def start_automatic_zap_service(config: dict):
    """TBD"""
    pass

def start_whatweb_service(config: dict | None):
    """TBD"""
    pass

def vuln_search_query(technology: str|list[dict], session_name: str) -> bool:
    """
    Queries vulnerabilities found in a fingerprinted technology.
    :param technology: a technology or list of technologies
    :param session_name: name of the session
    """
    if technology is None or len(technology) == 0:
        return False
    _temp = []
    _commands = ["./search_vulns.py", "-u", "--include-single-version-vulns", "-f", "json", "-o", f"/home/search_vulns/reports/{session_name}.json"]
    if type(technology) is str:
        _temp.append(f"{technology}")
    else:
        for dictionary in technology:
            for key, value in dictionary.items():
                if type(value) is list: # multiple versions detected
                    for version in value:
                        _temp.append(f"{key} {version}")
                else:
                    _temp.append(f"{key} {value}")
    for query in _temp:
        _commands.append("-q")
        _commands.append(query)

    #Can be changed to a more bash environment where we do docker exec into a running container with the command
    #This can incur less overhead of starting a new container and monitor the health of the running one.
    client = docker.from_env()
    containers = client.containers.list(all=True)

    if len(_commands) == 0: # No fingerprinted technology with versions are found
        return False

    try:
        if len(containers) > 0:
            for container in containers:
                if container.name == "search_vulns" and container.status != "running":
                    container.remove()
        client.containers.run(
                "search_vulns",
                tty=True,
                name="search_vulns",
                volumes={"D:\\Coding_Projects\\Python\\RestackAPI\\temp\\search_vulns": {"bind": "/home/search_vulns/reports", "mode":"rw"}}, #TODO: Change path to ENV
                command=_commands,
            )
        return True
    except Exception as e:
        print(f"An error occurred: \n {e}")
        return False

def parse_query(session_name:str = None) -> dict:
    with open(f"{DEV_ENV['report_paths']['searchVulns']}\\{session_name}.json","r") as f:
        queries = json.load(f)
        _returnable = {"found": {}, "not_found": []}
        for key, value in queries.items():
            if type(value) is list:
                _returnable["found"][key] = value
            else:
                _returnable["not_found"].append({key: "No vulnerabilities found"})
        return _returnable