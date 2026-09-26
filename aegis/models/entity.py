from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class Entity:
    """The subject of a security signal (process, network connection, file, or registry)."""
    type: str  # "process" | "connection" | "file" | "persistence" | "host"
    id: str    # Unique stable identifier (e.g., pid:start_time, path, or remote_ip:port)
    name: str
    pid: Optional[int] = None
    parent_pid: Optional[int] = None
    cmdline: Optional[str] = None
    path: Optional[str] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    metadata: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)

    def key(self) -> str:
        return f"{self.type}:{self.id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "id": self.id,
            "key": self.key(),
            "name": self.name,
            "pid": self.pid,
            "parent_pid": self.parent_pid,
            "cmdline": self.cmdline,
            "path": self.path,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "metadata": self.metadata,
        }
