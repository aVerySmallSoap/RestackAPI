import os
from typing import Optional

from loguru import logger

from modules.interfaces.builders.IConfigBuilder import IConfigBuilder
from modules.interfaces.enums.restack_enums import WapitiArgs
from modules.utils.load_configs import DEV_ENV


class WapitiConfigBuilder(IConfigBuilder):
    _wapiti_base_path = DEV_ENV["report_paths"]["wapiti"]
    _args: list[str] = ["-u", "-m", "-o", "-S", "--max-scan-time", "--tasks"]
    _commands: list[str] = [
        "wapiti",
        "-v",
        "2",
        "-f",
        "json",
        "-l",
        "2",
        "--headless",
        "hidden",
        "--flush-session",
        "--scope", "url",  # PERFORMANCE: only scan exact URL
    ]

    # == Configurable ==
    _url: Optional[str] = None  # Flag: -u !!REQUIRED
    _modules: Optional[list[str]] = None  # Flag: -m
    _path: Optional[str] = None  # Flag: -o
    _scan: Optional[str] = None  # Flag: -S | Scan aggression type
    _scan_time: Optional[str] = None  # Flag: --max-scan-time
    _concurrent_tasks: Optional[str] = None  # Flag: --tasks
    _custom_args: Optional[list[str]] = None
    _is_overridden: bool = (
        False  # Check if the user overrides with special custom arguments
    )

    # == validation ==
    _invalid_args: list[WapitiArgs] = []

    def url(self, url: str):
        self._url = url
        return self

    def modules(self, modules: list[str]):
        # FIX: Logic was backwards - if modules is None, use default, otherwise use provided
        if modules is None or len(modules) == 0:
            self._modules = ["common"]
        else:
            self._modules = modules
        return self

    def output_path(self, session: str):
        try:
            if session is None or session == "":
                raise ValueError("Session ID cannot be None or empty")
            # Use os.path.join for cross-platform compatibility
            self._path = os.path.join(self._wapiti_base_path, f"{session}.json")
            logger.debug(f"Wapiti output path set to: {self._path}")
            return self
        except ValueError as e:
            logger.error(f"Invalid session ID: {e}")
            raise

    def scan_aggression(self, level: str = "normal"):
        self._scan = level
        return self

    def max_scan_time(self, timeout: str = "300"):
        """Maximum scan time in seconds."""
        self._scan_time = timeout
        return self

    def max_concurrent_tasks(self, max_concurrent_tasks: str = "8"):
        self._concurrent_tasks = max_concurrent_tasks
        return self

    def _module_builder(self):
        if len(self._modules) > 1:
            return ",".join(self._modules)
        else:
            return self._modules[0]

    def validate_args(self) -> bool:
        """Check if all arguments are valid."""
        if self._url is None:
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

        if len(self._invalid_args) > 0:
            logger.warning(f"Invalid arguments detected: {self._invalid_args}")

        return len(self._invalid_args) == 0

    def _validate_custom_args(self) -> bool:
        """TBD - Validate custom arguments don't contain malicious code"""
        # For now, just return True
        return True

    def _set_defaults(self):
        """Checks if all arguments are valid, if not, builds a valid set of default arguments."""
        if not self.validate_args():
            for error in self._invalid_args:
                match error:
                    case WapitiArgs.MODULES:
                        logger.warning("No modules specified, using 'common'")
                        self.modules(["common"])
                    case WapitiArgs.PATH:
                        logger.error(
                            "No output path specified! This will cause scan to fail."
                        )
                        # Don't set a default "invalid" path - this should fail
                        raise ValueError("Output path is required but was not set")
                    case WapitiArgs.SCAN_TYPE:
                        self.scan_aggression()
                    case WapitiArgs.SCAN_TIME:
                        self.max_scan_time()
                    case WapitiArgs.CONCURRENT_TASKS:
                        self.max_concurrent_tasks()
                    case WapitiArgs.URL:
                        logger.error("No URL specified! Cannot run scan.")
                        raise ValueError("URL is required but was not set")

    def build(self) -> list:
        """Build the final Wapiti command."""
        if self._is_overridden:
            return self._custom_args

        # Validate and set defaults
        self._set_defaults()

        # Build command
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

        logger.debug(f"Built Wapiti command: {' '.join(self._commands)}")
        return self._commands
