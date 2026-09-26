from __future__ import annotations
import os
import subprocess
from pathlib import Path
from aegis.collectors.base import BaseCollector
from aegis.models.signal import Signal, Category, Severity, MITRETactic
from aegis.models.entity import Entity


class LivePersistenceCollector(BaseCollector):
    name = "live_persistence_collector"
    description = "Scans system persistence footholds (LaunchAgents, cron jobs, autostart entries)"

    def collect(self) -> list[Signal]:
        signals: list[Signal] = []

        # 1. macOS LaunchAgents / LaunchDaemons
        launch_dirs = [
            Path(os.path.expanduser("~/Library/LaunchAgents")),
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]

        for ldir in launch_dirs:
            if not ldir.exists():
                continue
            try:
                for plist in ldir.glob("*.plist"):
                    plist_name = plist.name
                    entity = Entity(
                        type="persistence",
                        id=str(plist.resolve()),
                        name=plist_name,
                        path=str(plist),
                        metadata={"type": "LaunchAgent/Daemon", "directory": str(ldir)},
                    )

                    # Flag plists from unknown third-parties or suspicious names
                    is_suspicious = any(k in plist_name.lower() for k in ["updater", "agent", "daemon", "service", "tmp"])
                    # Check if referencing binaries in /tmp or user cache
                    try:
                        content = plist.read_text(errors="ignore")
                        has_tmp = "/tmp" in content or "curl" in content or "sh" in content
                    except Exception:
                        has_tmp = False

                    if has_tmp or is_suspicious:
                        signals.append(Signal(
                            id=f"persist_plist_{plist_name}",
                            category=Category.PERSISTENCE,
                            source_check=self.name,
                            severity=Severity.HIGH if has_tmp else Severity.MEDIUM,
                            confidence=0.85,
                            entity=entity,
                            description=f"Autostart launch item detected: {plist_name}" + (" [Executes from /tmp or script]" if has_tmp else ""),
                            mitre_tactic=MITRETactic.PERSISTENCE,
                            mitre_technique="T1547: Boot or Logon Autostart Execution",
                            metadata={"plist_path": str(plist), "has_tmp": has_tmp},
                        ))
                    else:
                        signals.append(Signal(
                            id=f"persist_plist_{plist_name}",
                            category=Category.PERSISTENCE,
                            source_check=self.name,
                            severity=Severity.INFO,
                            confidence=0.9,
                            entity=entity,
                            description=f"Standard launch agent registered: {plist_name}",
                            mitre_tactic=MITRETactic.PERSISTENCE,
                            mitre_technique="T1547: Boot or Logon Autostart Execution",
                            metadata={"plist_path": str(plist)},
                        ))
            except Exception:
                continue

        # 2. Check Crontab
        try:
            res = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and res.stdout.strip():
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entity = Entity(
                            type="persistence",
                            id=f"cron:{line[:30]}",
                            name=f"Cron: {line[:25]}...",
                            metadata={"cron_entry": line},
                        )
                        signals.append(Signal(
                            id=f"persist_cron_{abs(hash(line))}",
                            category=Category.PERSISTENCE,
                            source_check=self.name,
                            severity=Severity.MEDIUM,
                            confidence=0.9,
                            entity=entity,
                            description=f"Active user cron job configured: {line}",
                            mitre_tactic=MITRETactic.PERSISTENCE,
                            mitre_technique="T1053.003: Cron Job",
                            metadata={"cron": line},
                        ))
        except Exception:
            pass

        return signals
