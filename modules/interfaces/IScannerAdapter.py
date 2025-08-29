from abc import ABC, abstractmethod

class IScannerAdapter(ABC):
    @abstractmethod
    def start_scan(self, config: dict, url:str):
        """This function should start a tool scan"""
        pass

    @abstractmethod
    def stop_scan(self, scan_id: str|int) -> int:
        """This function should stop an ongoing tool scan if the tool supports sessions."""
        pass

    @abstractmethod
    def generate_config(self, user_config: dict) -> dict:
        """This function should generate a dictionary from a list of user defined configurations"""
        pass

    @abstractmethod
    def parse_results(self, path: str) -> dict:
        """This function should parse the tools results and convert them into SARIF as the standard format."""
        pass