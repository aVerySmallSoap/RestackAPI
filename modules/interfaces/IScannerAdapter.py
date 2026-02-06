from abc import ABC, abstractmethod


class IScannerAdapter(ABC):

    @abstractmethod
    def start_scan(self, config: dict, **kwargs):
        pass

    @abstractmethod
    def stop_scan(self, session: str):
        pass

    @abstractmethod
    def parse_results(self, **config) -> dict:
        pass
