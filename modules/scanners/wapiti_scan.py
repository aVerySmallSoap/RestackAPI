from modules.utils.configurator import Configurator
import subprocess

# Update wapiti
#TODO: TRACK OF VULN DATABASE UPDATES
def scan(url, path) -> int:
    """Activate a scan using wapiti. Returns 1 if successful, 0 otherwise."""
    # process = subprocess.Popen(["wapiti", "--update"])
    # process.wait()
    # print("wapiti updated")

    # Start running config
    config = Configurator()
    config.set_url(url)
    config.set_path(path)
    test = config.configure()
    p = subprocess.Popen(test)
    p.wait()
    return 1 #TODO: find what the process returns or just return the status code