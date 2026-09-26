from __future__ import annotations
from typing import Any

MITRE_MATRIX: dict[str, dict[str, Any]] = {
    "TA0001": {
        "name": "Initial Access",
        "description": "Techniques that use various entry vectors to gain an initial foothold.",
        "techniques": {
            "T1190": "Exploit Public-Facing Application",
            "T1566": "Phishing",
            "T1078": "Valid Accounts",
        },
    },
    "TA0002": {
        "name": "Execution",
        "description": "Techniques that result in adversary-controlled code running on a local or remote system.",
        "techniques": {
            "T1059": "Command and Scripting Interpreter",
            "T1059.004": "Unix Shell / Reverse Shell",
            "T1204": "User Execution",
        },
    },
    "TA0003": {
        "name": "Persistence",
        "description": "Techniques that adversaries use to keep access across restarts and changed credentials.",
        "techniques": {
            "T1547": "Boot or Logon Autostart Execution",
            "T1543": "Create or Modify System Process",
            "T1053": "Scheduled Task / Cron Job",
        },
    },
    "TA0004": {
        "name": "Privilege Escalation",
        "description": "Techniques to gain higher-level permissions on a system.",
        "techniques": {
            "T1548": "Abuse Elevation Control Mechanism",
            "T1068": "Exploitation for Privilege Escalation",
        },
    },
    "TA0005": {
        "name": "Defense Evasion",
        "description": "Techniques used to avoid detection throughout their compromise.",
        "techniques": {
            "T1036": "Masquerading (System Binary Spoofing)",
            "T1027": "Obfuscated Files or Information",
            "T1562": "Impair Defenses / Disable Monitoring",
        },
    },
    "TA0006": {
        "name": "Credential Access",
        "description": "Techniques for stealing credentials like passwords and tokens.",
        "techniques": {
            "T1003": "OS Credential Dumping (Keychain / LSASS)",
            "T1555": "Credentials from Password Stores",
        },
    },
    "TA0009": {
        "name": "Collection",
        "description": "Techniques adversaries use to gather information and sources.",
        "techniques": {
            "T1113": "Screen Capture",
            "T1125": "Video / Camera Capture",
            "T1056": "Input Capture / Keylogging",
        },
    },
    "TA0011": {
        "name": "Command and Control",
        "description": "Techniques used to communicate with systems under control within a victim network.",
        "techniques": {
            "T1071": "Application Layer Protocol (C2 Beaconing)",
            "T1571": "Non-Standard Port Communication",
            "T1573": "Encrypted Channel",
        },
    },
    "TA0040": {
        "name": "Impact",
        "description": "Techniques to disrupt, destroy, or manipulate systems and data.",
        "techniques": {
            "T1486": "Data Encrypted for Impact (Ransomware)",
            "T1489": "Service Stop",
        },
    },
}


def get_mitre_summary(active_incidents: list[Any]) -> list[dict[str, Any]]:
    """Generates MITRE ATT&CK Matrix coverage with hit counts for SOC dashboard."""
    hits: dict[str, int] = {}
    technique_hits: dict[str, list[str]] = {}

    for inc in active_incidents:
        for tactic in getattr(inc, "mitre_tactics", []):
            code = tactic.split(":")[0].strip()
            hits[code] = hits.get(code, 0) + 1
        for tech in getattr(inc, "mitre_techniques", []):
            tech_code = tech.split(":")[0].strip()
            technique_hits.setdefault(tech_code, []).append(inc.title)

    matrix_view = []
    for tactic_id, info in MITRE_MATRIX.items():
        tactic_hit_count = hits.get(tactic_id, 0)
        matrix_view.append({
            "tactic_id": tactic_id,
            "tactic_name": info["name"],
            "description": info["description"],
            "hit_count": tactic_hit_count,
            "status": "COMPROMISED" if tactic_hit_count > 0 else "CLEAR",
            "techniques": [
                {
                    "technique_id": t_id,
                    "technique_name": t_name,
                    "triggered": t_id in technique_hits,
                    "incidents": technique_hits.get(t_id, []),
                }
                for t_id, t_name in info["techniques"].items()
            ],
        })
    return matrix_view
