from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from typing import Callable, Any
from aegis.models.signal import Signal, Category, Severity, MITRETactic
from aegis.models.entity import Entity
from aegis.models.incident import Incident, ContainmentStatus
from aegis.graph.entity_graph import EntityGraph


@dataclass
class Rule:
    id: str
    title_template: str
    condition: Callable[[Entity, list[Signal], set[Category]], bool]
    severity: Severity
    explanation_template: str
    remediation_template: str
    plain_english_template: str
    user_precautions: list[str]
    mitre_tactics: list[str]
    mitre_techniques: list[str]

    def evaluate(self, entity: Entity, signals: list[Signal], categories: set[Category]) -> Incident | None:
        if self.condition(entity, signals, categories):
            inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
            return Incident(
                incident_id=inc_id,
                rule_id=self.id,
                title=self.title_template.format(entity=entity.name),
                severity=self.severity,
                entity=entity,
                evidence=signals,
                explanation=self.explanation_template.format(
                    entity=entity.name,
                    path=entity.path or entity.id,
                    pid=entity.pid or "N/A"
                ),
                remediation=self.remediation_template.format(entity=entity.name),
                plain_english_summary=self.plain_english_template.format(entity=entity.name),
                user_precautions=[p.format(entity=entity.name) for p in self.user_precautions],
                mitre_tactics=self.mitre_tactics,
                mitre_techniques=self.mitre_techniques,
                confidence=min(1.0, sum(s.confidence for s in signals) / max(len(signals), 1)),
                status=ContainmentStatus.OPEN,
            )
        return None


def _has_category(categories: set[Category], *needed: Category) -> bool:
    return all(c in categories for c in needed)


def _count_categories(categories: set[Category], *candidates: Category) -> int:
    return sum(1 for c in candidates if c in categories)


RULES: list[Rule] = [
    # 1. Advanced Persistent Threat / C2 Beaconing
    Rule(
        id="apt_c2_beaconing",
        title_template="APT Command & Control Beacon: {entity}",
        condition=lambda e, sigs, cats: (
            _has_category(cats, Category.NETWORK)
            and any(s.metadata.get("c2_candidate") or s.metadata.get("external_connection") for s in sigs)
            and (
                any(s.category == Category.PERSISTENCE for s in sigs)
                or any(s.metadata.get("signed") is False for s in sigs if s.category == Category.APPLICATION)
            )
        ),
        severity=Severity.CRITICAL,
        explanation_template=(
            "Binary '{entity}' is establishing outbound network telemetry to an untrusted external IP "
            "while maintaining startup persistence or running unsigned code. This matches standard C2 (Command & Control) "
            "beaconing behavior."
        ),
        remediation_template="Immediately sever process sockets, terminate PID {entity}, and quarantine the binary.",
        plain_english_template=(
            "A hidden, unverified program called '{entity}' is secretly phoning home to an unknown computer on the internet "
            "every few seconds, and has set itself to automatically turn on every time you restart your machine. "
            "This is how attackers establish remote control over a compromised device."
        ),
        user_precautions=[
            "Click 'Execute SOAR Isolation' to freeze and terminate {entity} immediately.",
            "Disconnect your Wi-Fi or internet temporarily if multiple unknown connections are active.",
            "Change passwords for accounts recently accessed on this device.",
            "Inspect your Startup and Launch items to ensure no duplicate copies remain.",
        ],
        mitre_tactics=["TA0011: Command and Control", "TA0003: Persistence"],
        mitre_techniques=["T1071: Application Layer Protocol", "T1547: Boot or Logon Autostart"],
    ),

    # 2. Covert Privacy / Surveillance Spyware
    Rule(
        id="covert_surveillance_spyware",
        title_template="Covert Surveillance / Spyware Activity: {entity}",
        condition=lambda e, sigs, cats: (
            _has_category(cats, Category.PRIVACY)
            and (
                any(s.metadata.get("screen_capture") or s.metadata.get("keylogging") or s.metadata.get("cam_mic") for s in sigs)
            )
            and (
                _count_categories(cats, Category.PERSISTENCE, Category.NETWORK) >= 1
                or any(s.metadata.get("signed") is False for s in sigs if s.category == Category.APPLICATION)
            )
        ),
        severity=Severity.HIGH,
        explanation_template=(
            "Process '{entity}' is accessing sensitive input/screen captures without recognized developer signature "
            "and has active persistence or outbound communication hooks."
        ),
        remediation_template="Revoke screen recording/accessibility permissions, isolate process, and inspect installation vector.",
        plain_english_template=(
            "An unauthorized application named '{entity}' has silently tapped into your computer's screen, keyboard, "
            "or microphone. It could be taking secret screenshots or recording passwords as you type them."
        ),
        user_precautions=[
            "Revoke 'Screen Recording' and 'Accessibility' permissions for unrecognized apps in System Settings.",
            "Isolate the program immediately using the SOAR button.",
            "Cover your webcam physically or check your camera indicator light.",
            "Do not enter sensitive financial or private credentials until this application is quarantined.",
        ],
        mitre_tactics=["TA0009: Collection", "TA0005: Defense Evasion"],
        mitre_techniques=["T1113: Screen Capture", "T1056: Input Capture"],
    ),

    # 3. Interactive Reverse Shell
    Rule(
        id="interactive_reverse_shell",
        title_template="Interactive Reverse Shell Detected: {entity}",
        condition=lambda e, sigs, cats: (
            any(s.metadata.get("reverse_shell") for s in sigs)
            or (
                e.name in ["sh", "bash", "zsh", "nc", "netcat", "powershell", "cmd.exe"]
                and any(s.category == Category.NETWORK and s.metadata.get("external_connection") for s in sigs)
                and any(s.metadata.get("unusual_parent") for s in sigs)
            )
        ),
        severity=Severity.CRITICAL,
        explanation_template=(
            "Shell interpreter '{entity}' was spawned by a non-interactive service or web daemon "
            "with a direct interactive TCP socket attached. High probability of an active remote exploit."
        ),
        remediation_template="Execute immediate emergency SOAR process kill, isolate host network interface, and dump process memory.",
        plain_english_template=(
            "A hacker has successfully broken into a background program on your computer and opened a direct, "
            "live command-line doorway ('reverse shell'). They can type commands directly into your system as if they "
            "were sitting at your keyboard."
        ),
        user_precautions=[
            "Hit 'Execute SOAR Isolation' to instantly kill the terminal connection and socket.",
            "Isolate the machine from your local home or office network to prevent lateral infection.",
            "Check what background service (e.g. web server, python script, node process) was exploited to spawn this shell.",
            "Review system authorization logs for any newly created user accounts.",
        ],
        mitre_tactics=["TA0002: Execution", "TA0011: Command and Control"],
        mitre_techniques=["T1059.004: Unix Shell / Reverse Shell", "T1571: Non-Standard Port"],
    ),

    # 4. System Binary Masquerading / Process Impersonation
    Rule(
        id="system_binary_masquerade",
        title_template="Masquerading System Daemon: {entity}",
        condition=lambda e, sigs, cats: (
            any(s.metadata.get("masquerading") for s in sigs)
            or (
                e.name in ["svchost.exe", "launchd_agent", "csrss.exe", "systemd_core", "kernel_task"]
                and any(s.metadata.get("suspicious_location") for s in sigs)
            )
        ),
        severity=Severity.HIGH,
        explanation_template=(
            "Process '{entity}' uses a known OS system daemon name but executes from an unprivileged path "
            "with missing or mismatched digital signatures (Defense Evasion)."
        ),
        remediation_template="Verify legitimate binary hash against OS baseline, kill process, and quarantine file location.",
        plain_english_template=(
            "A program is wearing a disguise: it gave itself an official-sounding name like '{entity}' to trick you into "
            "thinking it's part of macOS or Windows, but it is running out of a temporary folder or Downloads directory "
            "where real operating system files never belong."
        ),
        user_precautions=[
            "Quarantine and delete the file immediately.",
            "Never approve permission popups asking for administrator privileges for files running in Downloads or Temp.",
            "Check the folder path shown in the incident details to see where it was downloaded from.",
        ],
        mitre_tactics=["TA0005: Defense Evasion"],
        mitre_techniques=["T1036: Masquerading"],
    ),

    # 5. Ransomware Canary / File Encryption Spike
    Rule(
        id="ransomware_crypto_activity",
        title_template="Ransomware Encryption Heuristic: {entity}",
        condition=lambda e, sigs, cats: (
            any(s.metadata.get("high_entropy_writes") or s.metadata.get("canary_tripped") for s in sigs)
        ),
        severity=Severity.CRITICAL,
        explanation_template=(
            "Process '{entity}' triggered high-entropy file writes across user documents or modified "
            "deployed canary trap files. Signature behavior matches active ransomware encryption."
        ),
        remediation_template="HALT PROCESS IMMEDIATELY (SIGSTOP), freeze file system writes, and preserve volume shadow copies.",
        plain_english_template=(
            "CRITICAL ALERT: '{entity}' is actively scrambling and encrypting your personal documents, photos, and files "
            "at high speed. This is the behavior of Ransomware attempting to hold your data hostage for extortion."
        ),
        user_precautions=[
            "The system automatically issues a SIGSTOP freeze to halt further file encryption in its tracks.",
            "DO NOT reboot your computer yet — active encryption keys might still be salvageable in memory.",
            "Disconnect external backup drives and network storage immediately to prevent the encryption from spreading.",
            "Quarantine the executable and verify which files were modified in the last 15 minutes.",
        ],
        mitre_tactics=["TA0040: Impact"],
        mitre_techniques=["T1486: Data Encrypted for Impact"],
    ),

    # 6. Credential Access / LSASS / Keychain Scraping
    Rule(
        id="credential_access_scraping",
        title_template="Unauthorized Credential Access: {entity}",
        condition=lambda e, sigs, cats: (
            any(s.metadata.get("credential_access") or s.metadata.get("keychain_dump") for s in sigs)
        ),
        severity=Severity.HIGH,
        explanation_template=(
            "Process '{entity}' queried OS credential vaults, browser SQLite stores, or memory regions "
            "associated with authentication tokens."
        ),
        remediation_template="Revoke session tokens, inspect process memory, and force password resets on compromised accounts.",
        plain_english_template=(
            "An app called '{entity}' tried to dig into your web browser password stores or system keychain "
            "to harvest saved logins, session cookies, and passwords."
        ),
        user_precautions=[
            "Change your primary email and banking passwords from another trusted device.",
            "Log out of active browser sessions (Google, GitHub, banking, social media).",
            "Enable Two-Factor Authentication (2FA) on all critical accounts.",
            "Terminate '{entity}' and inspect recent downloads.",
        ],
        mitre_tactics=["TA0006: Credential Access"],
        mitre_techniques=["T1003: OS Credential Dumping"],
    ),

    # 7. Unverified Listening Daemon
    Rule(
        id="unverified_listening_service",
        title_template="Unverified Listening Service: {entity}",
        condition=lambda e, sigs, cats: (
            _has_category(cats, Category.NETWORK)
            and any(s.metadata.get("listening") for s in sigs if s.category == Category.NETWORK)
            and any(s.metadata.get("signed") is False for s in sigs if s.category == Category.APPLICATION)
        ),
        severity=Severity.MEDIUM,
        explanation_template=(
            "Service '{entity}' is listening on local/external network sockets and lacks a valid digital signature. "
            "Common in backdoor remote access tools (RATs) or unmanaged dev servers."
        ),
        remediation_template="Confirm service legitimacy. If unauthorized, bind to localhost or terminate listening socket.",
        plain_english_template=(
            "A program called '{entity}' has opened an open communication port on your computer and is waiting for other "
            "computers to connect to it. If you didn't install this on purpose, it could allow people on your network to reach your machine."
        ),
        user_precautions=[
            "Check if you intentionally installed a server, game host, or remote access tool.",
            "If unrecognized, terminate the service and close the listening port.",
            "Ensure your computer's OS firewall is turned on.",
        ],
        mitre_tactics=["TA0011: Command and Control"],
        mitre_techniques=["T1571: Non-Standard Port Communication"],
    ),

    # 8. Outdated Software Vulnerability
    Rule(
        id="vulnerable_outdated_software",
        title_template="Unpatched Software Vulnerability: {entity}",
        condition=lambda e, sigs, cats: any(
            s.category == Category.VULNERABILITY and s.metadata.get("update_available")
            for s in sigs
        ),
        severity=Severity.LOW,
        explanation_template="{entity} is running a build with known security vulnerabilities and unpatched CVEs.",
        remediation_template="Apply upstream vendor security patches to {entity}.",
        plain_english_template=(
            "'{entity}' is an older version that has known security holes. Hackers know about these vulnerabilities "
            "and specifically target out-of-date apps to sneak into computers."
        ),
        user_precautions=[
            "Update {entity} directly from the official developer or App Store.",
            "Avoid clicking unofficial pop-up download links claiming to offer updates.",
            "Turn on automatic app updates in your settings.",
        ],
        mitre_tactics=["TA0001: Initial Access"],
        mitre_techniques=["T1190: Exploit Public-Facing Application"],
    ),
]


def run_rules(graph: EntityGraph) -> list[Incident]:
    """Runs all declarative correlation rules over the graph."""
    incidents = []
    for entity, entity_signals in graph.all_entity_signal_pairs():
        categories = {s.category for s in entity_signals}
        for rule in RULES:
            incident = rule.evaluate(entity, entity_signals, categories)
            if incident:
                incidents.append(incident)
    return incidents
