from abc import ABC, abstractmethod


class IThreadableScannerAdapter(ABC):

    @abstractmethod
    async def start_scan(self, config: dict, **kwargs):
        pass

    @abstractmethod
    def stop_scan(self, session: str):
        pass

    @abstractmethod
    async def parse_results(self, config: dict) -> dict:
        pass