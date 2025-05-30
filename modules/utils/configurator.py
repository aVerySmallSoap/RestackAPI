from typing import LiteralString
from modules.managers.report_manager import ReportManager

#TODO: Change default modules so scanning will be faster
#TODO: Limit the scan to at least 10 pages and with a depth of 3
#TODO: An average full wapiti scan takes about ~30 mins
#TODO: Each user has a separate scan configuration
class Configurator:
    """Handles the configuration of the wapiti library.
    Any additional arguments passed to this class are passed to wapiti.
    This class provides basic module arguments for a wapiti scan, however, it can be manually overridden.
    """
    _report_manager = ReportManager()
    #Required arguments
    _required_args = ["wapiti", "-u", "-m", "-v", "0", "-f", "json", "-l", "1", "-o"]

    #default options
    _default_modules:list = ["common"]
    _scan:str = "normal"
    _scan_time:int = 180
    _concurrent_tasks:int = 2

    #Non-default options
    _modules: list = None
    _url: str

    #final configuration
    _args = None

    #Non-shit
    _path:str = None

    def set_modules(self, _modules:list = None):
        self._modules = _modules

    def set_url(self, _url:str = None):
        if _url is None:
            print("something went wrong")
        else:
            self._url = _url

    def set_path(self, _path:str = None):
        if _path is None:
            print("something went wrong")
        else:
            self._path = _path

    def configure(self) -> list:
        """Runs a wapiti scan with the class' built configuration"""
        if self._args is None:
            self._args = []
            modules = self._module_builder()
            if self._url is not None:
                i=0
                while i < len(self._required_args):
                    self._args.append(self._required_args[i])
                    if i == 1:
                        self._args.append(self._url)
                    if i == 2:
                        self._args.append(modules)
                    i +=1
        self._args.append(self._path) #default path
        self._args.append("-S")
        self._args.append(self._scan)
        self._args.append("--max-scan-time")
        self._args.append(str(self._scan_time))
        self._args.append("--scope")
        self._args.append("domain")
        self._args.append("--tasks")
        self._args.append(str(self._concurrent_tasks)) # May improve performance
        return self._args

    def _module_builder(self) -> LiteralString:
        if self._modules is None:
            return ",".join(self._default_modules)
        else:
            return ",".join(self._modules)