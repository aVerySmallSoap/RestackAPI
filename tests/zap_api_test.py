import asyncio
import json
import os
import time

import docker
from zapv2 import ZAPv2

apiKey = "test"
# Run or create the docker container for ZAP
async def run_container(apikey:str):
    client = docker.from_env()
    containers = client.containers.list()
    for container in containers:
        if container.name == "zap":
            return
    client.containers.run("zaproxy/zap-stable",
                          ["zap.sh", "-daemon", "-host", "0.0.0.0", "-config", "api.addrs.addr.name=.*", "-config", "api.addrs.addr.regex=true", "-config", f"api.key={apiKey}"],
                          name="zap",
                          volumes={"D:\\Coding_Projects\\Python\\RestackAPI\\temp\\zap": {"bind": "/home/zap", "mode": "rw"}},
                          ports={"8080/tcp": 8080},
                          detach=True)

#create temporary file
if not os.path.isfile("../temp/zap/report.json"):
    open("../temp/zap/report.json", "x").close()

# localhost test use: host.docker.internal
target = 'http://host.docker.internal:8000'
zap = ZAPv2(apikey=apiKey)

def test_explore():
    print(f"Spider target: {target}")
    scanID = zap.spider.scan(target, recurse=True)
    while int(zap.spider.status(scanID)) < 100:
        print(f"Spider status %{zap.spider.status(scanID)}")
        time.sleep(2)

    print(f'Ajax spider target: {target}')
    zap.ajaxSpider.scan(target, inscope=False)
    timeout = time.time() + 60 * 2
    while zap.ajaxSpider.status == "running":
        if time.time() > timeout:
            break
        print(f"Ajax spider status: {zap.ajaxSpider.status}")
        time.sleep(2)

    print(f"Ajax spider completed")
    ajaxResults = zap.ajaxSpider.results()

    with open("../temp/zap/explore_report.json", "w") as writable:
        writable.write(json.dumps(ajaxResults))
        writable.flush()
        writable.close()

def test_active():
    print(f'Active Scanning target: {target}')
    scanID = zap.ascan.scan(target)
    while int(zap.ascan.status(scanID)) < 100:
        print(f"Scan progress %{zap.ascan.status(scanID)}")
        time.sleep(5)

    print(f"Active Scanning completed")
    print(zap.core.alerts(baseurl=target))
    with open("../temp/zap/report.json", "w") as writable:
        writable.write(json.dumps(zap.core.alerts(baseurl=target)))
        writable.flush()
        writable.close()

def test_passive():
    while int(zap.pscan.records_to_scan) > 0:
        # Loop until the passive scan has finished
        print('Records to passive scan : ' + zap.pscan.records_to_scan)
        time.sleep(2)

    print('Passive Scan completed')
    with open("../temp/zap/report.json", "w") as writable:
        writable.write(json.dumps(zap.core.alerts()))
        writable.flush()
        writable.close()

async def test():
    client = docker.from_env()
    await run_container("test")
    time.sleep(20) # wait for zap to load in docker
    for container in client.containers.list():
        if container.name == "zap":
            test_explore()
            test_active()

asyncio.run(test())