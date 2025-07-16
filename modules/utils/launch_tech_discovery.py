import json
import os

import docker
from docker.types import Mount

from modules.utils.env import ENV

# TODO LIST
# TODO: allow a controller to manage whatweb and its contents
# TODO: allow a scan from python (API) to a container

#TODO: check if a report file already exists, if so, flush its contents before writing
_local_report_path = "./temp/whatweb/report.json"
client = docker.from_env()

async def discover_then_volume(url:str):
    """Launches a docker container that utilizes the volume flag to store a whatweb report."""
    _sanitize_report()
    client.containers.run("whatweb",
                          ["./whatweb", "-a 3", "--log-json=./reports/report.json", url],
                          volumes={
                              ENV["report_paths"]["whatweb"]: {'bind': '/src/whatweb/reports', 'mode': 'rw'}},
                          auto_remove=True,
                          name="whatweb")

async def discover_then_mount(url:str):
    """Launches a docker container that utilizes the mount flag to store a whatweb report."""
    _sanitize_report()
    client.containers.run("whatweb",
                          ["./whatweb", "-a 3", "--log-json=./reports/report.json", url],
                          mounts=[Mount("/src/whatweb/reports", "/temp/reports")],
                          auto_remove=True)

def parse_mount_data():
    with open("//wsl.localhost/docker-desktop/mnt/docker-desktop-disk/data/docker/volumes/whatweb/_data/report.json", "r") as f:
        data = json.load(f)
        data = data[0]
        plugins = []
        for key, value in data["plugins"].items():
            plugins.append({key: value})
        return plugins

def parse_volume_data():
    with open(_local_report_path, "r") as f:
        data = json.load(f)
        data = data[0]
        plugins = []
        for key, value in data["plugins"].items():
            plugins.append({key: value})
        return plugins

def fetch_plugins_data() -> list:
    with open(_local_report_path, "r") as f:
        data = json.load(f)
        f.close()
    return data[0]

#primitive implementation until docker manager is created
def _sanitize_report():
    """Checks to see if a file exists, if not, creates a new file; else, remove the files contents"""
    if not os.path.isfile(_local_report_path):
        open(_local_report_path, "x").close()
    elif os.path.getsize(_local_report_path) > 0:
        open(_local_report_path, "w").close() # maybe redundant