from __future__ import annotations
import psutil
from typing import Optional
from aegis.collectors.base import BaseCollector
from aegis.models.signal import Signal, Category, Severity, MITRETactic
from aegis.models.entity import Entity

SUSPICIOUS_C2_PORTS = {4444, 5555, 6667, 1337, 31337, 8888, 9001, 5900}


class LiveNetworkCollector(BaseCollector):
    name = "live_network_collector"
    description = "Inspects active TCP/UDP sockets, remote IP endpoints, and listening services"

    def collect(self) -> list[Signal]:
        signals: list[Signal] = []

        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, PermissionError):
            # In restricted environments, fallback to process-by-process connection check
            connections = []
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    for conn in proc.connections(kind='inet'):
                        connections.append(conn)
                except Exception:
                    continue
        except Exception:
            connections = []

        seen_entities: dict[int, Entity] = {}

        for conn in connections:
            try:
                pid = conn.pid
                if not pid:
                    continue

                laddr = conn.laddr
                raddr = conn.raddr
                status = conn.status

                if pid not in seen_entities:
                    try:
                        p = psutil.Process(pid)
                        p_name = p.name()
                        p_exe = p.exe()
                        p_cmd = " ".join(p.cmdline()[:4])
                    except Exception:
                        p_name = f"proc_{pid}"
                        p_exe = None
                        p_cmd = None

                    entity = Entity(
                        type="process",
                        id=f"{pid}:{p_exe or p_name}",
                        name=p_name,
                        pid=pid,
                        path=p_exe,
                        cmdline=p_cmd,
                    )
                    seen_entities[pid] = entity
                else:
                    entity = seen_entities[pid]

                # Check 1: Listening services on all interfaces (0.0.0.0 or [::])
                if status == psutil.CONN_LISTEN:
                    lport = laddr.port if laddr else 0
                    is_public = laddr.ip in ["0.0.0.0", "::"] if laddr else False

                    # Check for suspicious listening ports
                    sev = Severity.HIGH if lport in SUSPICIOUS_C2_PORTS else (Severity.MEDIUM if is_public else Severity.INFO)
                    signals.append(Signal(
                        id=f"net_listen_{pid}_{lport}",
                        category=Category.NETWORK,
                        source_check=self.name,
                        severity=sev,
                        confidence=0.88,
                        entity=entity,
                        description=f"Process '{entity.name}' listening on port {lport} ({'Public/All Interfaces' if is_public else 'Localhost'})",
                        mitre_tactic=MITRETactic.COMMAND_AND_CONTROL,
                        mitre_technique="T1571: Non-Standard Port Communication",
                        metadata={
                            "listening": True,
                            "port": lport,
                            "ip": laddr.ip if laddr else None,
                            "public": is_public,
                        },
                    ))

                # Check 2: Established outbound external connections
                elif status == psutil.CONN_ESTABLISHED and raddr:
                    rip = raddr.ip
                    rport = raddr.port

                    # Filter out local loopback (127.0.0.1, ::1)
                    if not rip.startswith("127.") and rip != "::1":
                        is_suspicious_port = rport in SUSPICIOUS_C2_PORTS
                        sev = Severity.CRITICAL if is_suspicious_port else Severity.MEDIUM

                        signals.append(Signal(
                            id=f"net_estab_{pid}_{rip}_{rport}",
                            category=Category.NETWORK,
                            source_check=self.name,
                            severity=sev,
                            confidence=0.85 if is_suspicious_port else 0.65,
                            entity=entity,
                            description=f"Outbound connection established to {rip}:{rport}" + (" [KNOWN C2/RAT PORT]" if is_suspicious_port else ""),
                            mitre_tactic=MITRETactic.COMMAND_AND_CONTROL,
                            mitre_technique="T1071: Application Layer Protocol (C2 Beaconing)",
                            metadata={
                                "external_connection": True,
                                "c2_candidate": is_suspicious_port,
                                "remote_ip": rip,
                                "remote_port": rport,
                            },
                        ))

            except Exception:
                continue

        return signals
