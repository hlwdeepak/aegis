from __future__ import annotations
from collections import defaultdict
from typing import Any, Optional, Iterator
from aegis.models.signal import Signal, Category, Severity
from aegis.models.entity import Entity


class EntityGraph:
    """
    Multi-dimensional Entity Correlation Graph.
    Maintains entities, attached telemetry signals, parent-child process lineage,
    network relationships, and topological blast-radius.
    """

    def __init__(self):
        self._entities: dict[str, Entity] = {}
        self._signals_by_entity: dict[str, list[Signal]] = defaultdict(list)
        # Relationships: (source_key, target_key) -> relation_type (e.g. "SPAWNED", "COMMUNICATES_WITH", "PERSISTS_VIA")
        self._edges: list[dict[str, str]] = []

    def add_entity(self, entity: Entity) -> None:
        self._entities[entity.key()] = entity

    def add_signal(self, signal: Signal) -> None:
        entity = signal.entity
        key = entity.key()
        self._entities[key] = entity
        self._signals_by_entity[key].append(signal)

    def add_relation(self, source: Entity, target: Entity, relation_type: str = "ASSOCIATED_WITH") -> None:
        self.add_entity(source)
        self.add_entity(target)
        edge = {
            "source": source.key(),
            "target": target.key(),
            "type": relation_type,
        }
        if edge not in self._edges:
            self._edges.append(edge)

    def entities(self) -> list[Entity]:
        return list(self._entities.values())

    def get_entity(self, key: str) -> Optional[Entity]:
        return self._entities.get(key)

    def signals_for(self, entity: Entity) -> list[Signal]:
        return self._signals_by_entity[entity.key()]

    def categories_present(self, entity: Entity) -> set[Category]:
        return {s.category for s in self.signals_for(entity)}

    def all_entity_signal_pairs(self) -> Iterator[tuple[Entity, list[Signal]]]:
        for key, entity in self._entities.items():
            yield entity, self._signals_by_entity[key]

    def get_blast_radius(self, entity: Entity) -> list[str]:
        """Finds all connected entities directly impacted by this node."""
        key = entity.key()
        connected = set()
        for edge in self._edges:
            if edge["source"] == key:
                connected.add(edge["target"])
            elif edge["target"] == key:
                connected.add(edge["source"])
        return list(connected)

    def to_vis_graph(self, incidents: list[Any] = None) -> dict[str, Any]:
        """
        Exports the graph structure for interactive Vis.js / D3 rendering.
        Colors nodes dynamically based on maximum observed risk & incident severity.
        """
        incident_entity_keys = {}
        if incidents:
            for inc in incidents:
                ek = inc.entity.key()
                incident_entity_keys[ek] = inc.severity.value

        nodes = []
        for key, entity in self._entities.items():
            signals = self._signals_by_entity[key]
            # Determine maximum severity
            max_sev = "info"
            if key in incident_entity_keys:
                max_sev = incident_entity_keys[key]
            elif signals:
                weights = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                max_sig = max(signals, key=lambda s: weights.get(s.severity.value, 0))
                max_sev = max_sig.severity.value

            # Styling colors
            color_map = {
                "critical": "#ff0055",
                "high": "#ff3366",
                "medium": "#ff9900",
                "low": "#00d4ff",
                "informational": "#00ff88",
            }
            border_map = {
                "critical": "#ff0055",
                "high": "#ff4477",
                "medium": "#ffbb33",
                "low": "#33e0ff",
                "informational": "#33ff99",
            }

            node_color = color_map.get(max_sev, "#00ff88")
            node_border = border_map.get(max_sev, "#33ff99")

            # Labeling and icon representation
            shape = "box"
            if entity.type == "process":
                icon = "⚙️"
                shape = "box"
            elif entity.type == "connection":
                icon = "🌐"
                shape = "ellipse"
            elif entity.type == "persistence":
                icon = "⚓"
                shape = "diamond"
            elif entity.type == "file":
                icon = "📁"
                shape = "hexagon"
            else:
                icon = "🖥️"
                shape = "box"

            nodes.append({
                "id": key,
                "label": f"{icon} {entity.name}\n[{max_sev.upper()}]",
                "title": f"<b>Type:</b> {entity.type}<br><b>ID:</b> {entity.id}<br><b>Signals:</b> {len(signals)}<br><b>Cmd:</b> {entity.cmdline or 'N/A'}",
                "shape": shape,
                "color": {
                    "background": "#121826",
                    "border": node_border,
                    "highlight": {"background": "#1e293b", "border": "#ffffff"},
                },
                "font": {"color": "#f1f5f9", "face": "Inter, sans-serif", "size": 13},
                "borderWidth": 2 if max_sev in ["high", "critical"] else 1,
                "shadow": True if max_sev in ["high", "critical"] else False,
                "severity": max_sev,
                "entity_type": entity.type,
                "signal_count": len(signals),
            })

        # Process automatic parent-child relationships if present
        edges = list(self._edges)
        for entity in self._entities.values():
            if entity.parent_pid:
                # Find parent process
                for candidate in self._entities.values():
                    if candidate.type == "process" and candidate.pid == entity.parent_pid:
                        p_edge = {"source": candidate.key(), "target": entity.key(), "type": "SPAWNED"}
                        if p_edge not in edges:
                            edges.append(p_edge)

        formatted_edges = []
        for i, edge in enumerate(edges):
            formatted_edges.append({
                "id": f"e{i}",
                "from": edge["source"],
                "to": edge["target"],
                "label": edge["type"],
                "arrows": "to",
                "color": {"color": "#475569", "highlight": "#38bdf8"},
                "font": {"color": "#94a3b8", "size": 10, "align": "middle"},
                "dashes": edge["type"] in ["ASSOCIATED_WITH", "PERSISTS_VIA"],
            })

        return {"nodes": nodes, "edges": formatted_edges}
