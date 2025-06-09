import subprocess
import sys

subprocess.check_call([
    sys.executable,
    "-m",
    "pip",
    "install",
    "wapiti3",
    "Flask",
    "flask-cors",
    "tz",
    "SQLAlchemy",
    "SQLAlchemy-Utils",
    "psycopg2",
    "bs4",
    "beautifulsoup4",
    "requests",
    "ijson",
])