from typing import Optional

from modules.interfaces.builders.IConfigBuilder import IConfigBuilder
from modules.interfaces.enums.WapitiArguments import WapitiArgs
from modules.utils.load_configs import DEV_ENV


class WapitiConfigBuilder(IConfigBuilder):
    _args:list[str] = ["-u", "-m", "-o", "-S", "--max-scan-time", "--tasks"]
    _commands:list[str] = ["wapiti", "-v", "0", "-f", "json", "-l", "2", "--flush-session","--headless", "hidden"]

    #== Configurable ==
    _url: Optional[str] = None # Flag: -u !!REQUIRED
    _modules: Optional[list[str]] = None # Flag: -m
    _path: Optional[str] = None # Flag: -o
    _scan: Optional[str] = None # Flag: -S | Scan aggression type
    _scan_time: Optional[str] = None # Flag: --max-scan-time
    _concurrent_tasks: Optional[str] = None # Flag: --tasks
    _custom_args: Optional[list[str]] = None
    _is_overridden: bool = False # Check if the user overrides with special custom arguments

    #== validation ==
    _invalid_args:list[WapitiArgs] = []

    def url(self, url: str):
        self._url = url
        return self

    def modules(self, modules: list[str]):
        if self._modules is None:
            self._modules = ["common"]
            return self
        self._modules = modules
        return self

    def output_path(self, path: str = f"{DEV_ENV["report_paths"]["wapiti"]}\\report.json"):
        self._path = path
        return self

    def scan_aggression(self, level: str = "normal"):
        self._scan = level
        return self

    def max_scan_time(self, timeout: str = "180"):
        """Maximum scan time in seconds."""
        self._scan_time = timeout
        return self

    def max_concurrent_tasks(self, max_concurrent_tasks: str = "2"):
        self._concurrent_tasks = max_concurrent_tasks
        return self

    def _module_builder(self):
        if len(self._modules) > 1:
            return ",".join(self._modules)
        else:
            return self._modules[0]

    def validate_args(self) -> bool:
        """Check if all arguments are valid."""
        if self._url is None: # Find a better way to do this lol
            self._invalid_args.append(WapitiArgs.URL)
        if self._modules is None:
            self._invalid_args.append(WapitiArgs.MODULES)
        if self._path is None:
            self._invalid_args.append(WapitiArgs.PATH)
        if self._scan is None:
            self._invalid_args.append(WapitiArgs.SCAN_TYPE)
        if self._scan_time is None:
            self._invalid_args.append(WapitiArgs.SCAN_TIME)
        if self._concurrent_tasks is None:
            self._invalid_args.append(WapitiArgs.CONCURRENT_TASKS)
        return len(self._invalid_args) == 0

    # TODO: Check if passed arguments execute arbitrary code
    def _validate_custom_args(self) -> bool:
        """TBD"""
        pass

    def _set_defaults(self):
        """Checks if all arguments are valid, if not, builds a valid set of default arguments."""
        if not self.validate_args():
            for error in self._invalid_args:
                match error:
                    case WapitiArgs.MODULES:
                        self.modules(["common"])
                    case WapitiArgs.PATH:
                        self.output_path()
                    case WapitiArgs.SCAN_TYPE:
                        self.scan_aggression()
                    case WapitiArgs.SCAN_TIME:
                        self.max_scan_time()
                    case WapitiArgs.CONCURRENT_TASKS:
                        self.max_concurrent_tasks()

    def build(self) -> list:
        if self._is_overridden:
            return self._custom_args

        if not self._validate_custom_args():
            self._set_defaults()
        for args in self._args:
            self._commands.append(args)
            match args:
                case "-u":
                    self._commands.append(self._url)
                case "-m":
                    modules = self._module_builder()
                    self._commands.append(modules)
                case "-o":
                    self._commands.append(self._path)
                case "-S":
                    self._commands.append(self._scan)
                case "--max-scan-time":
                    self._commands.append(self._scan_time)
                case "--tasks":
                    self._commands.append(self._concurrent_tasks)
        return self._commands