import os

def check_directories():
    """This functions should check the existence of several required directories.
    These directories are reports and temp"""
    if not os.path.exists("./reports"):
        os.mkdir("./reports")
    if not os.path.exists("./temp"):
        os.mkdir("./temp")