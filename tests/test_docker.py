import json

import docker
from docker.types import Mount

from modules.utils.env import ENV

# TODO LIST
# TODO: allow a controller to manage whatweb and its contents
# TODO: allow a scan from python (API) to a container

#TODO: check if a report file already exists, if so, flush its contents before writing
client = docker.from_env()

def volume_test():
    client.containers.run("whatweb",
                          ["./whatweb", "-a 3", "--log-json=./reports/report.json", "https://dnsc.edu.ph/"],
                          volumes={
                              ENV["report_paths"]["whatweb"]: {'bind': '/src/whatweb/reports', 'mode': 'rw'}},
                          auto_remove=True)

def mount_test():
    client.containers.run("whatweb",
                          ["./whatweb", "-a 3", "--log-json=./reports/report.json", "https://dnsc.edu.ph/"],
                          mounts=[Mount("/src/whatweb/reports", "./temp/reports")],
                          auto_remove=True)

def mount_log():
    with open("//wsl.localhost/docker-desktop/mnt/docker-desktop-disk/data/docker/volumes/whatweb/_data/report.json") as f:
        data = json.load(f)
        for category in data[0]:
            print(category)

def vol_log():
    with open("../temp/whatweb/report.json") as f:
        data = json.load(f)
        for category in data[0]:
            print(category)

volume_test()
vol_log()