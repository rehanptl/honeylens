"""Step 2 and 3 of the pipeline.

  cluster_sessions():  every finished session gets a fingerprint -> cluster
  analyze_clusters():  each NEW cluster is explained once by the LLM

Because 12,000 sessions usually collapse into a few dozen clusters, we make a
few dozen LLM calls instead of 12,000. That's the main cost trick.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from . import config, mitre
from .fingerprint import classify_session, normalized_commands

log = logging.getLogger(__name__)

# Clusters that need no LLM: the label is obvious from what happened.
STATIC = {
    "scan": {
        "name": "Port scan / banner grab",
        "intent": "reconnaissance",
        "summary": "Connected to SSH and left without trying a password.",
        "explanation": "These are internet-wide scanners checking which hosts run SSH and "
        "what software version they advertise, usually to pick targets for later.",
        "severity": "low",
        "techniques": [{"id": "T1595", "evidence": "TCP connect + SSH banner exchange, no login"}],
    },
    "bruteforce": {
        "name": "SSH password brute force",
        "intent": "credential_theft",
        "summary": "Tried username/password pairs, none worked.",
        "explanation": "Automated bots cycle through common or leaked credentials hoping one "
        "works. Top usernames and passwords are on the overview page.",
        "severity": "medium",
        "techniques": [
            {"id": "T1110.001", "evidence": "repeated failed logins"},
            {"id": "T1133", "evidence": "targets exposed SSH service"},
        ],
    },
    "login_only": {
        "name": "Credential check (login, no commands)",
        "intent": "credential_theft",
        "summary": "Logged in successfully, then disconnected without doing anything.",
        "explanation": "Many botnets split the job: one bot finds working passwords and "
        "reports them back, another comes later to use them. This is the first half.",
        "severity": "medium",
        "techniques": [
            {"id": "T1110.001", "evidence": "password guessing before success"},
            {"id": "T1078.001", "evidence": "logged in with a default/weak account"},
        ],
    },
}


def _now():
    return datetime.now(timezone.utc)


def validate(raw: dict, source: str) -> dict:
    """Keep only real ATT&CK IDs and clean up fields from the LLM."""
    techniques, rejected = [], []
    seen = set()
    for t in raw.get("techniques", []):
        info = mitre.enrich(str(t.get("id", "")))
        if info is None:
            rejected.append(str(t.get("id")))
            continue
        if info["id"] in seen:
            continue
        seen.add(info["id"])
        info["evidence"] = str(t.get("evidence", ""))[:300]
        techniques.append(info)

    from .llm import INTENTS

    intent = str(raw.get("intent", "other")).lower().strip()
    severity = str(raw.get("severity", "medium")).lower().strip()
    return {
        "name": str(raw.get("name", "Unnamed pattern"))[:120],
        "intent": intent if intent in INTENTS else "other",
        "summary": str(raw.get("summary", ""))[:500],
        "explanation": str(raw.get("explanation", ""))[:3000],
        "severity": severity if severity in ("low", "medium", "high") else "medium",
        "techniques": techniques,
        "rejected_techniques": rejected,
        "iocs": [str(i)[:300] for i in raw.get("iocs", [])][:30],
        "source": source,
        "analyzed_at": _now(),
    }


def cluster_sessions(db, limit: int = 5000) -> int:
    cutoff = _now() - timedelta(minutes=config.STALE_SESSION_MINUTES)
    query = {
        "clustered": False,
        "$or": [{"closed": True}, {"last_seen": {"$lt": cutoff}}],
    }
    n = 0
    for s in db.sessions.find(query).limit(limit):
        cid, kind = classify_session(s)
        old = s.get("cluster_id")

        if old != cid:
            if old:  # session grew (e.g. more commands arrived) -> move it
                db.clusters.update_one({"_id": old}, {"$inc": {"session_count": -1}})
            new_cluster = {
                "kind": kind,
                "created": _now(),
                "sample_session": s["_id"],
                "normalized": normalized_commands([c["input"] for c in s.get("commands", [])])[:200],
                "needs_analysis": kind == "commands",
            }
            if kind != "commands":
                new_cluster["analysis"] = validate(STATIC[kind], "static")
            db.clusters.update_one(
                {"_id": cid},
                {
                    "$setOnInsert": new_cluster,
                    "$inc": {"session_count": 1},
                    "$min": {"first_seen": s.get("start")},
                    "$max": {"last_seen": s.get("last_seen")},
                    "$addToSet": {"src_ips": s.get("src_ip")},
                },
                upsert=True,
            )
        else:
            db.clusters.update_one({"_id": cid}, {"$max": {"last_seen": s.get("last_seen")}})

        db.sessions.update_one({"_id": s["_id"]}, {"$set": {"clustered": True, "cluster_id": cid}})
        n += 1
    return n


MAX_HARD_ERRORS = 3
_TEMPORARY = ("503", "429", "500", "UNAVAILABLE", "RESOURCE_EXHAUSTED", "overloaded",
              "high demand", "timed out", "timeout", "Connection")


def is_temporary(error: Exception) -> bool:
    """Server busy / rate limited / network blip: worth retrying later, not the cluster's fault."""
    text = f"{type(error).__name__} {error}"
    return any(marker.lower() in text.lower() for marker in _TEMPORARY)


def analyze_clusters(db, analyzer, max_calls: int) -> int:
    from .llm import RuleAnalyzer

    done = 0
    pending = db.clusters.find({"needs_analysis": True}).sort("session_count", -1).limit(max_calls)
    for cluster in pending:
        sample = db.sessions.find_one({"_id": cluster["sample_session"]}) or {}
        commands = [c["input"] for c in sample.get("commands", [])]
        args = (
            commands,
            sample.get("downloads", []),
            {"username": sample.get("username"), "password": sample.get("password")},
        )
        try:
            raw, source = analyzer.analyze(*args), analyzer.source
        except Exception as e:
            if is_temporary(e):
                # The LLM service is busy. Don't hammer it or count this against the
                # cluster: stop for this cycle and retry everything next cycle.
                log.warning("LLM temporarily unavailable (%s); retrying next cycle", str(e)[:120])
                break
            # A real failure for this cluster (e.g. the model returned unusable output).
            errors = cluster.get("hard_errors", 0) + 1
            log.warning("analysis failed for %s (%d/%d): %s", cluster["_id"], errors, MAX_HARD_ERRORS, e)
            if errors < MAX_HARD_ERRORS:
                db.clusters.update_one({"_id": cluster["_id"]}, {"$set": {"hard_errors": errors}})
                continue
            # Give up on the LLM for this one, but still label it with the keyword rules
            # so it never sits on "Pending" forever.
            raw, source = RuleAnalyzer().analyze(*args), "rules (LLM failed)"
        result = validate(raw, source)
        db.clusters.update_one(
            {"_id": cluster["_id"]},
            {"$set": {"analysis": result, "needs_analysis": False,
                      "sample_commands": commands[:200]}},
        )
        log.info("analyzed %s -> %s (%s)", cluster["_id"], result["name"], result["source"])
        done += 1
    return done
