"""Read Cowrie's JSON log files and turn raw events into MongoDB documents.

Cowrie writes one JSON object per line, e.g.
  {"eventid": "cowrie.login.failed", "username": "root", "password": "123456",
   "src_ip": "1.2.3.4", "session": "a1b2c3", "timestamp": "2026-11-18T12:00:00.000Z"}

We remember how many bytes of each file we've already read (keyed by the file's
inode, so it still works after Cowrie rotates cowrie.json -> cowrie.json.2026-11-18).
"""
from __future__ import annotations

import glob
import hashlib
import json
import logging
import os
from datetime import datetime, timezone

from pymongo import InsertOne, UpdateOne
from pymongo.errors import BulkWriteError

log = logging.getLogger(__name__)

MAX_COMMANDS_PER_SESSION = 500
MAX_DOWNLOADS_PER_SESSION = 50


def parse_ts(value: str) -> datetime:
    # Cowrie: "2026-11-18T12:00:00.123456Z"
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def event_to_ops(event: dict, raw_line: str):
    """Map one Cowrie event to (session_update, login_insert_or_None)."""
    eid = event.get("eventid", "")
    sid = event.get("session")
    if not sid or "timestamp" not in event:
        return None, None

    ts = parse_ts(event["timestamp"])
    update = {
        "$setOnInsert": {"clustered": False, "closed": False},
        "$min": {"start": ts},
        "$max": {"last_seen": ts},
        "$set": {},
        "$inc": {},
    }
    if event.get("src_ip"):
        update["$set"]["src_ip"] = event["src_ip"]
    if event.get("sensor"):
        update["$set"]["sensor"] = event["sensor"]

    login_doc = None

    if eid == "cowrie.session.connect":
        update["$set"]["dst_port"] = event.get("dst_port")
        update["$set"]["protocol"] = event.get("protocol", "ssh")
    elif eid == "cowrie.client.version":
        update["$set"]["client_version"] = str(event.get("version", ""))[:200]
    elif eid == "cowrie.client.kex":
        update["$set"]["hassh"] = event.get("hassh")
    elif eid in ("cowrie.login.failed", "cowrie.login.success"):
        ok = eid.endswith("success")
        update["$inc"]["login_success" if ok else "login_failed"] = 1
        if ok:
            update["$set"]["username"] = event.get("username")
            update["$set"]["password"] = event.get("password")
        login_doc = {
            "_id": hashlib.sha1(raw_line.encode()).hexdigest(),  # dedupe on re-read
            "ts": ts,
            "session": sid,
            "src_ip": event.get("src_ip"),
            "username": str(event.get("username", ""))[:200],
            "password": str(event.get("password", ""))[:200],
            "success": ok,
        }
    elif eid == "cowrie.command.input":
        update["$push"] = {
            "commands": {
                "$each": [{"ts": ts, "input": str(event.get("input", ""))[:2000]}],
                "$slice": MAX_COMMANDS_PER_SESSION,
            }
        }
        update["$inc"]["command_count"] = 1
    elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
        update["$push"] = {
            "downloads": {
                "$each": [{
                    "url": event.get("url") or event.get("filename"),
                    "sha256": event.get("shasum"),
                }],
                "$slice": MAX_DOWNLOADS_PER_SESSION,
            }
        }
    elif eid == "cowrie.session.closed":
        update["$set"]["closed"] = True
        update["$set"]["duration"] = event.get("duration")
        # if new events arrive later, the session gets re-analyzed
    else:
        # other events (tcpip forwarding, terminal size, ...) just bump last_seen
        pass

    # any new activity means the session changed -> (re)analyze it
    update["$set"]["clustered"] = False
    # a field can't be in both $set and $setOnInsert
    for k in list(update["$setOnInsert"]):
        if k in update["$set"]:
            del update["$setOnInsert"][k]
    # Mongo rejects empty operators
    update = {k: v for k, v in update.items() if v}
    return UpdateOne({"_id": sid}, update, upsert=True), login_doc


def _file_key(path: str) -> str:
    st = os.stat(path)
    return f"{st.st_dev}:{st.st_ino}"


def ingest_file(db, path: str, batch_size: int = 2000) -> int:
    key = _file_key(path)
    state = db.ingest_state.find_one({"_id": key}) or {"offset": 0}
    offset = state["offset"]
    size = os.path.getsize(path)
    if size < offset:  # file was truncated / replaced
        offset = 0
    if size == offset:
        return 0

    count = 0
    session_ops, login_ops = [], []

    def flush():
        if session_ops:
            db.sessions.bulk_write(session_ops, ordered=True)
            session_ops.clear()
        if login_ops:
            try:
                db.logins.bulk_write(login_ops, ordered=False)
            except BulkWriteError as e:  # duplicate _id = already ingested; fine
                if any(err.get("code") != 11000 for err in e.details.get("writeErrors", [])):
                    raise
            login_ops.clear()

    with open(path, "rb") as f:
        f.seek(offset)
        for raw in f:
            if not raw.endswith(b"\n"):
                break  # Cowrie is mid-write; pick it up next cycle
            offset += len(raw)
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                log.warning("bad json line in %s", path)
                continue
            s_op, login = event_to_ops(event, line)
            if s_op is not None:
                session_ops.append(s_op)
            if login is not None:
                login_ops.append(InsertOne(login))
            count += 1
            if len(session_ops) >= batch_size:
                flush()
                db.ingest_state.update_one({"_id": key}, {"$set": {"offset": offset, "path": path}}, upsert=True)
    flush()
    db.ingest_state.update_one({"_id": key}, {"$set": {"offset": offset, "path": path}}, upsert=True)
    return count


def ingest_all(db, globs: list[str]) -> int:
    total = 0
    paths = sorted({p for g in globs for p in glob.glob(g) if os.path.isfile(p)})
    for path in paths:
        try:
            n = ingest_file(db, path)
        except OSError as e:
            log.warning("could not read %s: %s", path, e)
            continue
        if n:
            log.info("ingested %d events from %s", n, path)
        total += n
    return total
