from abc import ABC, abstractmethod

class IAsyncScannerAdapter(ABC):
    """Same as the IScannerAdapter interface but some of its methods are awaitable"""
    @abstractmethod
    async def start_scan(self, config: dict, url:str):
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