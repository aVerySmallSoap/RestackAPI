import json

import docker

from modules.utils.load_configs import DEV_ENV


def start_manual_zap_service(config: dict):
    client = docker.from_env()
    containers = client.containers.list(all=True)
    if len(containers) > 0:
        for container in containers:
            if container.name == "zap" and container.status != "running":
                container.start()
    else:
        client.containers.run("zaproxy/zap-stable",
                              ["zap.sh", "-daemon", "-host", "0.0.0.0", "-config", "api.addrs.addr.name=.*", "-config","api.addrs.addr.regex=true", "-config", f"api.key={config["apikey"]}"],
                              name="zap",
                              volumes={"D:\\Coding_Projects\\Python\\RestackAPI\\temp\\zap": {"bind": "/home/zap","mode": "rw"}}, #TODO: Change path to ENV
                              ports={"8080/tcp": 8080},
                              detach=True)

def start_automatic_zap_service(config: dict):
    """TBD"""
    pass

def start_whatweb_service(config: dict | None):
    """TBD"""
    pass

async def update_vuln_search_service():
    """Updates the search_vuln database in docker"""
    client = docker.from_env()
    client.containers.run("search_vulns", name="search_vulns", tty=True, command=["./search_vulns.py", "-u"])

def vuln_search_query(technology: str|list[dict], session_name: str):
    """
    Queries vulnerabilities found in a fingerprinted technology.
    :param technology: a technology or list of technologies
    :param session_name: name of the session
    """
    if technology is None or len(technology) == 0:
        return
    _temp = []
    _commands = ["./search_vulns.py", "--include-single-version-vulns", "-f", "json", "-o", f"/home/search_vulns/reports/{session_name}.json"]
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
    if len(containers) > 0:
        for container in containers:
            if container.name == "search_vulns" and container.status != "running":
                container.start()
                container.exec_run(_commands)
    else:
        client.containers.run(
            "search_vulns",
            tty=True,
            volumes={"D:\\Coding_Projects\\Python\\RestackAPI\\temp\\search_vulns": {"bind": "/home/search_vulns/reports","mode": "rw"}}, #TODO: Change path to ENV
            command=_commands,
        )

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