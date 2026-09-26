from __future__ import annotations
from abc import ABC, abstractmethod
from aegis.models.signal import Signal


class BaseCollector(ABC):
    """Abstract base class for all endpoint telemetry collectors."""

    name: str = "base_collector"
    description: str = "Base endpoint telemetry collector"

    @abstractmethod
    def collect(self) -> list[Signal]:
        """Gathers telemetry and emits atomic Signal objects."""
        pass
