from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from click import command


@dataclass
class BehaviorPattern:
    name: str
    stage: str
    severity: str
    keywords_sequence: List[List[str]]
    mitre_techniques: List[str]
    description: str


BEHAVIOR_PATTERNS = [
    BehaviorPattern(
        name="System Reconnaissance",
        stage="Reconnaissance",
        severity="MEDIUM",
        keywords_sequence=[
            ["whoami", "id"],
            ["uname", "hostname", "cat /proc/cpuinfo"],
        ],
        mitre_techniques=["T1082", "T1033"],
        description="Attacker collected user and system information.",
    ),
    BehaviorPattern(
        name="Network Reconnaissance",
        stage="Reconnaissance",
        severity="MEDIUM",
        keywords_sequence=[
            ["ifconfig", "ip a", "ip addr"],
            ["netstat", "ss -tuln", "route", "arp"],
        ],
        mitre_techniques=["T1016"],
        description="Attacker collected network configuration and connectivity information.",
    ),
    BehaviorPattern(
        name="Credential Discovery",
        stage="Credential Access",
        severity="HIGH",
        keywords_sequence=[
            ["/etc/passwd", "/etc/shadow", ".ssh/id_rsa", "authorized_keys"],
        ],
        mitre_techniques=["T1003", "T1552"],
        description="Attacker attempted to access credential or authentication files.",
    ),
    BehaviorPattern(
        name="Payload Download",
        stage="Payload Delivery",
        severity="HIGH",
        keywords_sequence=[
            ["wget", "curl", "ftp", "tftp"],
        ],
        mitre_techniques=["T1105"],
        description="Attacker downloaded or attempted to retrieve a remote payload.",
    ),
    BehaviorPattern(
        name="Malware Delivery & Execution",
        stage="Execution",
        severity="HIGH",
        keywords_sequence=[
            ["wget", "curl"],
            ["chmod +x", "chmod 777"],
            ["./", "sh ", "bash "],
        ],
        mitre_techniques=["T1105", "T1059"],
        description="Attacker downloaded a payload, made it executable, then attempted execution.",
    ),
    BehaviorPattern(
        name="Remote Script Execution",
        stage="Execution",
        severity="HIGH",
        keywords_sequence=[
            ["curl", "wget"],
            ["| bash", "| sh", "bash -c", "sh -c"],
        ],
        mitre_techniques=["T1105", "T1059"],
        description="Attacker attempted to directly execute a remote script.",
    ),
    BehaviorPattern(
        name="Persistence Attempt",
        stage="Persistence",
        severity="HIGH",
        keywords_sequence=[
            ["crontab", "/etc/cron", "systemctl", "service"],
        ],
        mitre_techniques=["T1053", "T1543"],
        description="Attacker attempted to create persistence using cron or services.",
    ),
    BehaviorPattern(
        name="Defense Evasion",
        stage="Defense Evasion",
        severity="HIGH",
        keywords_sequence=[
            ["history -c", "unset histfile", "rm -rf /var/log", ">/dev/null"],
        ],
        mitre_techniques=["T1070"],
        description="Attacker attempted to hide activity or remove traces.",
    ),
    BehaviorPattern(
        name="Crypto Mining Activity",
        stage="Impact",
        severity="HIGH",
        keywords_sequence=[
            ["xmrig", "minerd", "stratum+tcp", "crypto-pool", "monero"],
        ],
        mitre_techniques=["T1496"],
        description="Attacker attempted cryptocurrency mining activity.",
    ),
    BehaviorPattern(
        name="Lateral Movement Attempt",
        stage="Lateral Movement",
        severity="HIGH",
        keywords_sequence=[
            ["ssh root@", "ssh admin@", "ssh user@", "scp ", "sftp "],
        ],
        mitre_techniques=["T1021"],
        description="Attacker attempted SSH-based lateral movement.",
    ),
]


def is_noise_command(command: str) -> bool:
    noise_patterns = [
        "new connection:",
        "remote ssh version:",
        "ssh client hassh fingerprint:",
        "terminal size:",
        "connection lost",
        "<!doctype html>",
        "document",
    ]

    return any(pattern in command for pattern in noise_patterns)


def clean_command(value: str) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        return None

    command = value.strip().lower()

    if is_noise_command(command):
        return None

    return command


def extract_command_from_event(event: Any) -> Optional[str]:
    payload = getattr(event, "payload", None)

    if not isinstance(payload, dict):
        return None

    for field in ["input", "command", "message"]:
        command = clean_command(payload.get(field))

        if command:
            return command

    raw_event = payload.get("raw_event")

    if isinstance(raw_event, dict):
        for field in ["input", "command", "message"]:
            command = clean_command(raw_event.get(field))

            if command:
                return command

    return None


def normalize_session_commands(events: List[Any]) -> List[Dict[str, Any]]:
    ordered_events = sorted(events, key=lambda e: getattr(e, "timestamp", None))

    commands = []

    for event in ordered_events:
        command = extract_command_from_event(event)

        if command:
            commands.append(
                {
                    "event_id": getattr(event, "id", None),
                    "timestamp": getattr(event, "timestamp", None),
                    "command": command,
                }
            )

    return commands


def command_matches(command: str, keywords: List[str]) -> bool:
    return any(keyword in command for keyword in keywords)


def detect_pattern(
    commands: List[Dict[str, Any]],
    pattern: BehaviorPattern,
) -> Optional[Dict[str, Any]]:
    matched_steps = []
    current_index = 0

    for command_obj in commands:
        if current_index >= len(pattern.keywords_sequence):
            break

        command = command_obj["command"]
        expected_keywords = pattern.keywords_sequence[current_index]

        if command_matches(command, expected_keywords):
            matched_steps.append(command_obj)
            current_index += 1

    if current_index == len(pattern.keywords_sequence):
        return {
            "behavior_name": pattern.name,
            "stage": pattern.stage,
            "severity": pattern.severity,
            "description": pattern.description,
            "mitre_techniques": pattern.mitre_techniques,
            "detected_sequence": matched_steps,
            "confidence": calculate_confidence(pattern, matched_steps),
        }

    return None


def calculate_confidence(
    pattern: BehaviorPattern,
    matched_steps: List[Dict[str, Any]],
) -> float:
    base = 0.70

    if len(matched_steps) >= 2:
        base += 0.10

    if len(matched_steps) >= 3:
        base += 0.10

    if pattern.severity == "HIGH":
        base += 0.05

    return min(round(base, 2), 0.98)


def generate_attack_timeline(behaviors: List[Dict[str, Any]]) -> List[str]:
    timeline = []

    for behavior in behaviors:
        stage = behavior.get("stage")

        if stage and stage not in timeline:
            timeline.append(stage)

    return timeline


def calculate_overall_behavior_severity(behaviors: List[Dict[str, Any]]) -> str:
    if not behaviors:
        return "LOW"

    severities = [b["severity"] for b in behaviors]

    if "HIGH" in severities:
        return "HIGH"

    if "MEDIUM" in severities:
        return "MEDIUM"

    return "LOW"


def generate_behavior_summary(behaviors: List[Dict[str, Any]]) -> str:
    if not behaviors:
        return "No significant multi-step attacker behavior detected."

    timeline = generate_attack_timeline(behaviors)

    if timeline:
        return "Detected attacker behavior timeline: " + " → ".join(timeline)

    names = [b["behavior_name"] for b in behaviors]
    return "Detected attacker behaviors: " + " → ".join(names)


def analyze_session_behaviors(events: List[Any]) -> Dict[str, Any]:
    commands = normalize_session_commands(events)

    detected_behaviors = []

    for pattern in BEHAVIOR_PATTERNS:
        result = detect_pattern(commands, pattern)

        if result:
            detected_behaviors.append(result)

    attack_timeline = generate_attack_timeline(detected_behaviors)

    return {
        "commands_analyzed": len(commands),
        "behaviors": detected_behaviors,
        "attack_timeline": attack_timeline,
        "overall_behavior_severity": calculate_overall_behavior_severity(
            detected_behaviors
        ),
        "summary": generate_behavior_summary(detected_behaviors),
    }