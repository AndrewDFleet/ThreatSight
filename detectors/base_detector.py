from abc import ABC, abstractmethod
from typing import Optional
from models import Alert, Packet


class BaseDetector(ABC):
    @abstractmethod
    def process(self, packet: Packet) -> Optional[Alert]: ...

    @abstractmethod
    def reset(self) -> None: ...
