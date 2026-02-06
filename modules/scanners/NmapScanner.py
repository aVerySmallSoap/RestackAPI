# Future feature
# TODO: Build out and integrate Nmap as additional information gathered
from modules.interfaces.IScannerAdapter import IScannerAdapter


class NmapScanner(IScannerAdapter):
    def start_scan(self, config: dict, **kwargs):
        pass # Not yet supported

    def stop_scan(self, scan_id: str | int) -> int:
        pass # Not yet supported

    def generate_config(self, user_config: dict) -> dict:
        pass # Not yet supported

    def parse_results(self, path: str) -> dict:
        pass # Not yet supported
