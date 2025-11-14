# Future feature
# TODO: Build out and integrate Nikto as part of user requirements
from modules.interfaces.IScannerAdapter import IScannerAdapter


class NiktoScanner(IScannerAdapter):
    def start_scan(self, config: dict, url: str):
        pass

    def stop_scan(self, scan_id: str | int) -> int:
        pass

    def generate_config(self, user_config: dict) -> dict:
        pass

    def parse_results(self, path: str) -> dict:
        pass

