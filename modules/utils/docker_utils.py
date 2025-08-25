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

def start_automatic_zap_service(self, config: dict):
    pass

def start_whatweb_service(self, config: dict | None):
    pass
