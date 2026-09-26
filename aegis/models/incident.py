from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from aegis.models.signal import Signal, Severity, MITRETactic
from aegis.models.entity import Entity


class ContainmentStatus(str):
    OPEN = "ACTIVE_THREAT"
    CONTAINED = "CONTAINED_ISOLATED"
    RESOLVED = "RESOLVED"
    DISMISSED = "FALSE_POSITIVE"


@dataclass
class Incident:
    incident_id: str
    rule_id: str
    title: str
    severity: Severity
    entity: Entity
    evidence: list[Signal]
    explanation: str
    remediation: str
    plain_english_summary: str = ""
    user_precautions: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    confidence: float = 0.85
    status: str = ContainmentStatus.OPEN
    created_at: datetime = field(default_factory=datetime.utcnow)
    containment_actions_taken: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 2),
            "entity": self.entity.to_dict(),
            "evidence": [s.to_dict() for s in self.evidence],
            "evidence_count": len(self.evidence),
            "explanation": self.explanation,
            "remediation": self.remediation,
            "plain_english_summary": self.plain_english_summary,
            "user_precautions": self.user_precautions,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "containment_actions_taken": self.containment_actions_taken,
        }
