from __future__ import annotations
from aegis.graph.entity_graph import EntityGraph
from aegis.models.incident import Incident
from aegis.models.signal import Category, Severity
from aegis.models.entity import Entity

CATEGORY_LABELS = {
    Category.PROCESS: "Process Integrity",
    Category.NETWORK: "Network Perimeter",
    Category.PERSISTENCE: "Persistence & Autostart",
    Category.PRIVACY: "Privacy & Sensor Hooks",
    Category.APPLICATION: "Code Signatures",
    Category.VULNERABILITY: "Patch & Vulnerabilities",
    Category.INTEGRITY: "System Integrity",
}

SEVERITY_PENALTY = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 8,
    Severity.HIGH: 20,
    Severity.CRITICAL: 40,
}


def entity_risk_score(entity: Entity, graph: EntityGraph) -> float:
    signals = graph.signals_for(entity)
    return sum(s.weight() for s in signals)


def overall_posture_score(graph: EntityGraph, incidents: list[Incident]) -> int:
    """
    Computes global cyber hygiene & defense posture (0 - 100).
    Incidents reflect correlated active attacks and penalize heavily.
    """
    score = 100

    # Incident correlation penalties
    for incident in incidents:
        penalty = SEVERITY_PENALTY.get(incident.severity, 10)
        score -= penalty

    # Lingering isolated high/critical signals
    for entity in graph.entities():
        for s in graph.signals_for(entity):
            if s.severity in [Severity.HIGH, Severity.CRITICAL]:
                score -= 3
            elif s.severity == Severity.MEDIUM:
                score -= 1

    return max(0, min(100, score))


def category_status(graph: EntityGraph) -> dict[str, dict[str, str]]:
    """Worst status per category: Good / Attention / High Risk / Critical."""
    worst: dict[Category, Severity] = {}
    for entity in graph.entities():
        for s in graph.signals_for(entity):
            current = worst.get(s.category, Severity.INFO)
            severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            if severity_order.index(s.severity) > severity_order.index(current):
                worst[s.category] = s.severity

    status_badge = {
        Severity.INFO: {"label": "Optimal", "color": "#10b981", "badge": "🟢 OPTIMAL"},
        Severity.LOW: {"label": "Normal", "color": "#06b6d4", "badge": "🔵 NORMAL"},
        Severity.MEDIUM: {"label": "Elevated", "color": "#f59e0b", "badge": "🟠 ATTENTION"},
        Severity.HIGH: {"label": "High Threat", "color": "#ef4444", "badge": "🔴 HIGH RISK"},
        Severity.CRITICAL: {"label": "Critical Compromise", "color": "#ec4899", "badge": "⚡ CRITICAL"},
    }

    result = {}
    for cat, name in CATEGORY_LABELS.items():
        sev = worst.get(cat, Severity.INFO)
        result[name] = status_badge[sev]
    return result


def generate_executive_metrics(graph: EntityGraph, incidents: list[Incident]) -> dict:
    score = overall_posture_score(graph, incidents)
    cat_statuses = category_status(graph)

    # Posture rating
    if score >= 85:
        posture_tier = "SECURE / HARDENED"
        tier_color = "#10b981"
    elif score >= 65:
        posture_tier = "MODERATE POSTURE"
        tier_color = "#f59e0b"
    elif score >= 40:
        posture_tier = "COMPROMISED / HIGH RISK"
        tier_color = "#ef4444"
    else:
        posture_tier = "CRITICAL BREACH"
        tier_color = "#ec4899"

    total_signals = sum(len(graph.signals_for(e)) for e in graph.entities())

    return {
        "score": score,
        "posture_tier": posture_tier,
        "tier_color": tier_color,
        "incident_count": len(incidents),
        "total_signals": total_signals,
        "entity_count": len(graph.entities()),
        "categories": cat_statuses,
    }
