# Run command for Docker.
# docker run --rm -v .:/root/.config/subfinder -it projectdiscovery/subfinder \
# -d dnsc.edu.ph -o ./root/.config/subfinder/test.txt -oJ
import pathlib
from loguru import logger

import docker

from modules.utils.load_configs import DEV_ENV

base_path = f"{DEV_ENV['report_paths']['subfinder']}"

def run_scan():
    #mock params
    test_id = "test"
    test_target = "https://dnsc.edu.ph"
    #Launch container
    start_subfinder_container(test_id, test_target)
    # Parse output
    parse_output(test_id)

    # save to database

    # Cleanup
    cleanup(test_id)
    pass

def parse_output(session:str):
    logger.info(f"Parsing {session}")
    with open(f"{base_path}\\subfinder_{session}.txt") as f:
        links = [line.strip() for line in f]
        print(links)
    logger.info(f"Finished parsing {session}")

def cleanup(session:str):
    logger.info(f"Cleaning up {session}")
    pathlib.Path(f"{base_path}\\subfinder_{session}.txt").unlink()
    logger.info(f"Finished cleaning up {session}")

def reset_reports():
    logger.info(f"Cleaning up subfinder results")
    for file in pathlib.Path(base_path).glob("*"):
        file.unlink()
    logger.info(f"Finished cleaning up subfinder results")

# For utilities
def start_subfinder_container(session: str, target: str):
    logger.info(f"Starting subfinder container as {session}")
    client = docker.from_env()
    client.containers.run(
        image="projectdiscovery/subfinder",
        command=["-d", target, "-o", f"./root/.config/subfinder/reports/subfinder_{session}.txt"],
        volumes={
            f"{base_path}": {"bind": "/root/.config/subfinder/reports", "mode": "rw"}
        },
        name=f"subfinder_{session}",
        auto_remove=True
    )