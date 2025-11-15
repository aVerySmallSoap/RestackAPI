from enum import Enum

# Enumerations

class WapitiArgs(Enum):
    URL = 1
    MODULES = 2
    PATH = 3
    SCAN_TYPE = 4
    SCAN_TIME = 5
    CONCURRENT_TASKS = 6
    CUSTOM_ARGS = 7

# Enumerations as Types

class ScannerType(Enum):
    WAPITI = 1
    WHATWEB = 2
    ZAP = 3
    ZAP_AUTOMATION = 4 # Future feature
    FULL = 5

class ScanType(Enum):
    BASIC = 1
    FULL = 2
    CUSTOM = 3
    AUTOMATIC = 4

class ZAPScanType(Enum):
    PASSIVE = 1
    ACTIVE = 2
    API = 3
    AUTOMATIC = 4

