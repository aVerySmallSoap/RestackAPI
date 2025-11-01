
def check_url_local_test(url:str) -> str:
    """Check if a url contains localhost or 127.0.0.1 and returns the docker equivalent"""
    if url.__contains__("localhost") or url.__contains__("127.0.0.1"):
        return url.replace("localhost", "host.docker.internal")
    return url