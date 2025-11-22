from abc import ABC, abstractmethod


class IConfigBuilder(ABC):
    @abstractmethod
    def build(self) -> dict:
        pass
