from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import Any, Optional


class Severity(str, Enum):
    INFO = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    PROCESS = "process"
    PRIVACY = "privacy"
    PERSISTENCE = "persistence"
    NETWORK = "network"
    APPLICATION = "application"
    VULNERABILITY = "vulnerability"
    INTEGRITY = "integrity"


class MITRETactic(str, Enum):
    INITIAL_ACCESS = "TA0001: Initial Access"
    EXECUTION = "TA0002: Execution"
    PERSISTENCE = "TA0003: Persistence"
    PRIVILEGE_ESCALATION = "TA0004: Privilege Escalation"
    DEFENSE_EVASION = "TA0005: Defense Evasion"
    CREDENTIAL_ACCESS = "TA0006: Credential Access"
    DISCOVERY = "TA0007: Discovery"
    LATERAL_MOVEMENT = "TA0008: Lateral Movement"
    COLLECTION = "TA0009: Collection"
    COMMAND_AND_CONTROL = "TA0011: Command and Control"
    EXFILTRATION = "TA0010: Exfiltration"
    IMPACT = "TA0040: Impact"


@dataclass
class Signal:
    """Atomic telemetry event reported by endpoint collectors."""
    id: str
    category: Category
    source_check: str
    severity: Severity
    confidence: float  # 0.0 - 1.0
    entity: Any        # Entity instance (forward ref resolved at runtime)
    description: str
    mitre_tactic: Optional[MITRETactic] = None
    mitre_technique: Optional[str] = None  # e.g., "T1059: Command and Scripting Interpreter"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)

    def weight(self) -> float:
        """Weighted impact for scoring engine."""
        sev_weights = {
            Severity.INFO: 0.0,
            Severity.LOW: 1.5,
            Severity.MEDIUM: 4.0,
            Severity.HIGH: 8.5,
            Severity.CRITICAL: 15.0,
        }
        return sev_weights.get(self.severity, 1.0) * self.confidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "source_check": self.source_check,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 2),
            "entity_id": self.entity.key() if hasattr(self.entity, "key") else str(self.entity),
            "entity_name": getattr(self.entity, "name", "unknown"),
            "description": self.description,
            "mitre_tactic": self.mitre_tactic.value if self.mitre_tactic else None,
            "mitre_technique": self.mitre_technique,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }
