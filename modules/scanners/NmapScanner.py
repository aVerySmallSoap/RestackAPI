# Future feature
# TODO: Build out and integrate Nmap as additional information gathered
from modules.interfaces.IDeprecatedScannerAdapter import IDeprecatedScannerAdapter


class NmapScanner(IDeprecatedScannerAdapter):
    def start_scan(self, config: dict, url: str):
        pass

    def stop_scan(self, scan_id: str | int) -> int:
        pass

    def generate_config(self, user_config: dict) -> dict:
        pass

    def parse_results(self, path: str) -> dict:
        pass

