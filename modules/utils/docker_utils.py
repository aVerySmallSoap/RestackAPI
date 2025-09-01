import docker

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
                              volumes={"D:\\Coding_Projects\\Python\\RestackAPI\\temp\\zap": {"bind": "/home/zap","mode": "rw"}},
                              ports={"8080/tcp": 8080},
                              detach=True)

def start_automatic_zap_service(config: dict):
    """TBD"""
    pass

def start_whatweb_service(config: dict | None):
    """TBD"""
    pass

def update_vuln_search_service():
    """Updates the search_vuln database in docker"""
    client = docker.from_env()
    client.containers.run("search_vulns", auto_remove=True, tty=True, command=["./search_vulns.py", "-u"])

def vuln_search_query(technology: str|list[str]):
    """Queries vulnerabilities found in a fingerprinted technology.
    :param technology: a technology or list of technologies"""
    pass
