from __future__ import annotations
import os
import psutil
from typing import Optional
from aegis.collectors.base import BaseCollector
from aegis.models.signal import Signal, Category, Severity, MITRETactic
from aegis.models.entity import Entity

SUSPICIOUS_SYSTEM_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
    "launchd_agent", "systemd_core", "kernel_task_helper"
}

SUSPICIOUS_PATHS = [
    "/tmp", "/private/tmp", "/var/tmp", "/dev/shm",
    os.path.expanduser("~/.cache"),
]


class LiveProcessCollector(BaseCollector):
    name = "live_process_collector"
    description = "Inspects live OS process tree, executable lineage, and anomaly patterns"

    def __init__(self, sample_limit: int = 150):
        self.sample_limit = sample_limit

    def collect(self) -> list[Signal]:
        signals: list[Signal] = []
        count = 0

        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'username', 'cpu_percent']):
            if count >= self.sample_limit:
                break
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                name = pinfo['name'] or f"proc_{pid}"
                exe_path = pinfo['exe'] or ""
                ppid = pinfo['ppid']
                cmdline_list = pinfo['cmdline'] or []
                cmdline = " ".join(cmdline_list)

                # Skip idle / kernel pid 0
                if pid == 0:
                    continue

                entity = Entity(
                    type="process",
                    id=f"{pid}:{exe_path or name}",
                    name=name,
                    pid=pid,
                    parent_pid=ppid,
                    cmdline=cmdline[:200] if cmdline else None,
                    path=exe_path,
                    metadata={"username": pinfo.get('username')},
                )

                # Check 1: Process executing from suspicious / world-writable temp folders
                if exe_path:
                    for sp in SUSPICIOUS_PATHS:
                        if exe_path.startswith(sp):
                            signals.append(Signal(
                                id=f"proc_tmp_{pid}",
                                category=Category.PROCESS,
                                source_check=self.name,
                                severity=Severity.HIGH,
                                confidence=0.85,
                                entity=entity,
                                description=f"Process executing out of temporary path: {exe_path}",
                                mitre_tactic=MITRETactic.DEFENSE_EVASION,
                                mitre_technique="T1036: Masquerading",
                                metadata={"suspicious_location": True, "path": exe_path},
                            ))
                            break

                # Check 2: Binary name impersonating system daemon from non-system directory
                if name.lower() in SUSPICIOUS_SYSTEM_NAMES:
                    is_system_path = False
                    if exe_path:
                        lower_exe = exe_path.lower()
                        if "/system/" in lower_exe or "/usr/sbin" in lower_exe or "c:\\windows\\system32" in lower_exe:
                            is_system_path = True

                    if not is_system_path:
                        signals.append(Signal(
                            id=f"proc_masq_{pid}",
                            category=Category.PROCESS,
                            source_check=self.name,
                            severity=Severity.HIGH,
                            confidence=0.90,
                            entity=entity,
                            description=f"System binary spoofing detected: '{name}' running outside system root",
                            mitre_tactic=MITRETactic.DEFENSE_EVASION,
                            mitre_technique="T1036.005: Masquerading (Match Legitimate Name)",
                            metadata={"masquerading": True, "path": exe_path},
                        ))

                # Check 3: Suspicious shell invocation flags or encoded commands
                if cmdline:
                    lower_cmd = cmdline.lower()
                    if any(flag in lower_cmd for flag in ["base64 -d", "-encodedcommand", "curl | bash", "wget -q -o- | sh"]):
                        signals.append(Signal(
                            id=f"proc_obfuscated_{pid}",
                            category=Category.PROCESS,
                            source_check=self.name,
                            severity=Severity.CRITICAL,
                            confidence=0.92,
                            entity=entity,
                            description=f"Suspicious inline pipeline or encoded payload in command line: {cmdline[:80]}...",
                            mitre_tactic=MITRETactic.EXECUTION,
                            mitre_technique="T1059: Command and Scripting Interpreter",
                            metadata={"reverse_shell": True, "cmdline": cmdline},
                        ))

                count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        return signals
