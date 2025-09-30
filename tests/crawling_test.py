# This test should find almost all JS tied links
import asyncio
import subprocess

import docker

client = docker.from_env()

def _crawl_for_js(url:str):
    process = subprocess.Popen(["echo", url, "|", "docker", "run", "--rm", "-i", "hakrawler", "-subs", "-json"])
    process.wait()
    while not process.stdout.closed:
        with process.stdout.read() as line:
            print(line)

async def _crawl_for_links():
    pass


_crawl_for_js("https://google.com")