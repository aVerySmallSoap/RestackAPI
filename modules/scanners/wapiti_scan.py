from modules.utils.wapiti_configurator import WapitiConfigurator
import subprocess

# Update wapiti
#TODO: TRACK OF VULN DATABASE UPDATES
#TODO: find what the process returns or just return the status code
#TODO: find a more secure way of executing wapiti
def scan(url:str, path:str) -> int:
    """Activate a scan using wapiti"""
    # process = subprocess.Popen(["wapiti", "--update"])
    # process.wait()
    # print("wapiti updated")

    # Start running config
    config = WapitiConfigurator()
    config.set_url(url)
    config.set_path(path)
    test = config.configure()
    p = subprocess.Popen(test)
    p.wait()
    return 1