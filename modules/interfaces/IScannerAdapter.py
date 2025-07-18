from abc import ABC, abstractmethod

class IScannerAdapter(ABC):
    @abstractmethod
    def start_scan(self, config: dict):
        pass

    @abstractmethod
    def stop_scan(self, scan_id: str|int) -> int:
        pass

    @abstractmethod
    def generate_config(self, user_config: dict) -> dict:
        """Generates a config from a user request"""
        pass

    @abstractmethod
    def parse_results(self, path: str) -> dict:
        """Parses the results from the scan"""
        pass