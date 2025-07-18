import queue
import datetime

from modules.interfaces.enums.ScannerTypes import ScannerTypes
from modules.utils.load_env import ENV


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
    _wapiti_path = ENV["report_paths"]["wapiti"]
    _whatweb_path = ENV["report_paths"]["whatweb"]
    _zap_path = ENV["report_paths"]["zap"]

    def enqueue_session(self, scanner_type: ScannerTypes, start_time: datetime):
        # TODO: write to session database
        self._enqueue_name(start_time)
        self._ScanQueue.put({"scanner": scanner_type, "date": start_time})

    def dequeue_session(self):
        self._ScanQueue.task_done()

    def _enqueue_name(self, scan_time: datetime):
        self._NameQueue.put(scan_time.strftime("%Y%m%d_%I-%M-%S"))

    def _dequeue_name(self) -> str:
        return self._NameQueue.get()

    def generate_path(self, scanner_type: ScannerTypes) -> str:
        match scanner_type:
            case ScannerTypes.WAPITI:
                return f"{self._wapiti_path}\\{self._dequeue_name()}.json"
            case ScannerTypes.WHATWEB:
                return f"{self._whatweb_path}\\{self._dequeue_name()}.json"
            case ScannerTypes.ZAP:
                return f"{self._zap_path}\\{self._dequeue_name()}.json"
            case _:
                return ""

class ScannerWorker:
    pass
