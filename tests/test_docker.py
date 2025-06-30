import docker
from docker.types import Mount

client = docker.from_env()

client.containers.run("whatweb",
                      ["./whatweb", "-a 3", "--log-json=./reports/report.json", "https://dnsc.edu.ph/"],
                      mounts=[Mount("/src/whatweb/reports","whatweb")],
                      auto_remove=True)

# TODO LIST
# TODO: allow a controller to manage whatweb and its contents
# TODO: allow a scan from python (API) to a container
# TODO: retrieve scan results from container into python (API)