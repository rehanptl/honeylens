"""MITRE ATT&CK (Enterprise) techniques relevant to a Linux SSH honeypot.

This is an allow-list: if the LLM returns a technique ID that isn't here, we
drop it and count it as a rejected answer. That stops made-up IDs ("T9999")
from ever reaching the dashboard.
"""

TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# id: (name, primary tactic)
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1133": ("External Remote Services", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1078.001": ("Valid Accounts: Default Accounts", "Initial Access"),
    "T1078.003": ("Valid Accounts: Local Accounts", "Initial Access"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1059.006": ("Python", "Execution"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1098.004": ("SSH Authorized Keys", "Persistence"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1543.002": ("Systemd Service", "Persistence"),
    "T1037.004": ("RC Scripts", "Persistence"),
    "T1546.004": ("Unix Shell Configuration Modification", "Persistence"),
    "T1548.003": ("Sudo and Sudo Caching", "Privilege Escalation"),
    "T1070.003": ("Clear Command History", "Defense Evasion"),
    "T1070.004": ("File Deletion", "Defense Evasion"),
    "T1222.002": ("Linux and Mac File and Directory Permissions Modification", "Defense Evasion"),
    "T1562.001": ("Disable or Modify Tools", "Defense Evasion"),
    "T1562.004": ("Disable or Modify System Firewall", "Defense Evasion"),
    "T1564.001": ("Hidden Files and Directories", "Defense Evasion"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1110.004": ("Brute Force: Credential Stuffing", "Credential Access"),
    "T1003.008": ("/etc/passwd and /etc/shadow", "Credential Access"),
    "T1552.001": ("Credentials In Files", "Credential Access"),
    "T1552.004": ("Private Keys", "Credential Access"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1016": ("System Network Configuration Discovery", "Discovery"),
    "T1049": ("System Network Connections Discovery", "Discovery"),
    "T1033": ("System Owner/User Discovery", "Discovery"),
    "T1087.001": ("Account Discovery: Local Account", "Discovery"),
    "T1518.001": ("Security Software Discovery", "Discovery"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1090": ("Proxy", "Command and Control"),
    "T1572": ("Protocol Tunneling", "Command and Control"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1496": ("Resource Hijacking", "Impact"),
    "T1496.001": ("Resource Hijacking: Compute Hijacking", "Impact"),
    "T1498": ("Network Denial of Service", "Impact"),
    "T1485": ("Data Destruction", "Impact"),
    "T1489": ("Service Stop", "Impact"),
    "T1531": ("Account Access Removal", "Impact"),
}


def url_for(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def enrich(tid: str) -> dict | None:
    tid = tid.strip().upper()
    if tid not in TECHNIQUES:
        return None
    name, tactic = TECHNIQUES[tid]
    return {"id": tid, "name": name, "tactic": tactic, "url": url_for(tid)}


def prompt_table() -> str:
    """Compact list we hand to the LLM so it picks from real IDs."""
    return "\n".join(f"{tid}  {name}  [{tactic}]" for tid, (name, tactic) in TECHNIQUES.items())
