import queue
import datetime

from modules.interfaces.enums.ScannerTypes import ScannerTypes
from modules.utils.load_configs import DEV_ENV


class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class ScannerEngine(metaclass=Singleton):
    """Manages scan sessions"""
    _instance = None
    _ScanQueue = queue.Queue(maxsize=5)
    _NameQueue = queue.Queue(maxsize=5)

    # == Report paths ==
    _wapiti_path = DEV_ENV["report_paths"]["wapiti"]
    _whatweb_path = DEV_ENV["report_paths"]["whatweb"]
    _zap_path = DEV_ENV["report_paths"]["zap"]
    _full_scan_path = DEV_ENV["report_paths"]["full_scan"]

    def enqueue_session(self, scanner_type: ScannerTypes, start_time: datetime):
        self._enqueue_name(start_time)
        self._ScanQueue.put({"scanner": scanner_type, "date": start_time})

    def dequeue_session(self):
        self._ScanQueue.task_done()

    def enqueue_name(self, scan_time: datetime):
        self._NameQueue.put(scan_time.strftime("%Y%m%d_%I-%M-%S"))

    def dequeue_name(self) -> str:
        return self._NameQueue.get()

    def generate_file(self, scanner_type: ScannerTypes, path: str = None) -> str:
        """Generates the session name for the reports. The ``path`` parameter is used to override the default path check.
        :param scanner_type: Type of scanner
        :param path: Optional path to save the reports
        :return: The file path with the session name
        """
        if path is not None:
            return path
        match scanner_type:
            case ScannerTypes.WAPITI:
                return f"{self._wapiti_path}\\{self.dequeue_name()}.json"
            case ScannerTypes.WHATWEB:
                return f"{self._whatweb_path}\\{self.dequeue_name()}.json"
            case ScannerTypes.ZAP:
                return f"{self._zap_path}\\{self.dequeue_name()}.json"
            case ScannerTypes.FULL:
                return f"{self._full_scan_path}\\{self.dequeue_name()}.json"
            case _:
                return ""

class ScannerWorker:
    pass
