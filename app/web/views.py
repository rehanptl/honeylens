"""Server-rendered dashboard pages.

Each view queries MongoDB, shapes the numbers into plain Python lists, and hands
them to a Django template. The browser just receives finished HTML (with SVG
charts) - there is no JavaScript and no JSON API.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from django.http import Http404
from django.shortcuts import render

from honeylens import mitre
from honeylens.db import get_db

INTENT_LABELS = {
    "reconnaissance": "Reconnaissance",
    "cryptomining": "Cryptomining",
    "botnet_recruitment": "Botnet recruitment",
    "persistence": "Persistence",
    "credential_theft": "Credential theft",
    "malware_dropper": "Malware dropper",
    "defense_evasion": "Defense evasion",
    "proxy_or_tunnel": "Proxy / tunnel",
    "destructive": "Destructive",
    "other": "Other",
}


def _db():
    return get_db()


def _bars(rows, label_key="_id", value_key="n"):
    """[{_id, n}] -> [{label, value, pct}] for horizontal bar lists."""
    rows = list(rows)
    top = max((r[value_key] for r in rows), default=0) or 1
    return [{"label": str(r[label_key]), "value": r[value_key],
             "pct": round(100 * r[value_key] / top, 1)} for r in rows]


def _top(coll, field, match=None, limit=10):
    pipeline = []
    if match:
        pipeline.append({"$match": match})
    pipeline += [
        {"$group": {"_id": f"${field}", "n": {"$sum": 1}}},
        {"$sort": {"n": -1}},
        {"$limit": limit},
    ]
    return _bars(r for r in coll.aggregate(pipeline) if r["_id"] not in (None, ""))


def _daily_chart(db, days=30):
    """Login attempts per day -> geometry for an SVG column chart."""
    since = datetime.now(timezone.utc) - timedelta(days=days - 1)
    since = since.replace(hour=0, minute=0, second=0, microsecond=0)
    counts = {
        r["_id"]: r["n"]
        for r in db.logins.aggregate([
            {"$match": {"ts": {"$gte": since}}},
            {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$ts"}},
                        "n": {"$sum": 1}}},
        ])
    }
    w, h, pad_l, pad_b = 720, 200, 44, 22
    plot_w, plot_h = w - pad_l - 8, h - pad_b - 10
    top = max(counts.values(), default=0)
    nice = 10 ** max(len(str(top)) - 1, 0)
    y_max = max(((top // nice) + 1) * nice, 1)
    slot = plot_w / days
    bars = []
    for i in range(days):
        day = (since + timedelta(days=i)).strftime("%Y-%m-%d")
        n = counts.get(day, 0)
        bh = plot_h * n / y_max
        bars.append({
            "day": day, "n": n,
            "x": round(pad_l + i * slot + 1, 1), "w": round(max(slot - 2, 1), 1),
            "y": round(10 + plot_h - bh, 1), "h": round(bh, 1),
            "label": day[5:] if i % 5 == 0 else "",
            "lx": round(pad_l + i * slot + slot / 2, 1),
        })
    grid = [{"v": int(y_max * f), "y": round(10 + plot_h - plot_h * f, 1)} for f in (0, 0.5, 1)]
    return {"bars": bars, "grid": grid, "w": w, "h": h, "pad_l": pad_l,
            "base_y": 10 + plot_h, "right": w - 8, "label_y": h - 6, "has_data": top > 0}


def _technique_counts(clusters):
    """Sum sessions per technique across all analyzed clusters."""
    agg = {}
    for c in clusters:
        for t in (c.get("analysis") or {}).get("techniques", []):
            row = agg.setdefault(t["id"], {**t, "sessions": 0, "clusters": 0})
            row["sessions"] += c.get("session_count", 0)
            row["clusters"] += 1
    return agg


def overview(request):
    db = _db()
    sessions = db.sessions
    first = sessions.find_one(sort=[("start", 1)])
    last = sessions.find_one(sort=[("last_seen", -1)])
    unique_ips = next(iter(sessions.aggregate([
        {"$group": {"_id": "$src_ip"}}, {"$count": "n"}])), {"n": 0})["n"]
    days = 0
    if first and last:
        days = max((last["last_seen"] - first["start"]).days + 1, 1)

    clusters = list(db.clusters.find({}, {"analysis": 1, "session_count": 1, "kind": 1}))
    cmd_clusters = [c for c in clusters if c.get("kind") == "commands"]
    tech = sorted(_technique_counts(clusters).values(), key=lambda r: -r["sessions"])[:10]

    intents = defaultdict(int)
    for c in cmd_clusters:
        intents[(c.get("analysis") or {}).get("intent", "pending")] += c.get("session_count", 0)

    kpis = [
        ("Login attempts", db.logins.count_documents({})),
        ("Unique attacker IPs", unique_ips),
        ("Sessions", sessions.count_documents({})),
        ("Got a shell & ran commands", sessions.count_documents({"command_count": {"$gt": 0}})),
        ("Distinct attack scripts", len(cmd_clusters)),
        ("Days observed", days),
    ]
    top_clusters = list(db.clusters.find({"kind": "commands"}).sort("session_count", -1).limit(6))
    for c in top_clusters:
        c["cid"] = c["_id"]  # templates can't read attributes starting with "_"

    return render(request, "web/overview.html", {
        "kpis": kpis,
        "daily": _daily_chart(db),
        "usernames": _top(db.logins, "username"),
        "passwords": _top(db.logins, "password"),
        "ips": _top(db.logins, "src_ip"),
        "clients": _top(sessions, "client_version", limit=6),
        "techniques": _bars([{"_id": f'{t["id"]} {t["name"]}', "n": t["sessions"], "id": t["id"]}
                             for t in tech]),
        "intents": _bars(sorted(({"_id": INTENT_LABELS.get(k, k.title()), "n": v}
                                 for k, v in intents.items()), key=lambda r: -r["n"])),
        "top_clusters": top_clusters,
        "nav": "overview",
    })


def cluster_list(request):
    db = _db()
    q = {}
    kind = request.GET.get("kind", "commands")
    if kind in ("commands", "scan", "bruteforce", "login_only"):
        q["kind"] = kind
    elif kind != "all":
        kind = "commands"
        q["kind"] = kind
    intent = request.GET.get("intent")
    if intent in INTENT_LABELS:
        q["analysis.intent"] = intent
    clusters = []
    for c in db.clusters.find(q).sort("session_count", -1).limit(500):
        c["cid"] = c["_id"]
        c["ip_count"] = len(c.get("src_ips", []))
        clusters.append(c)
    return render(request, "web/clusters.html", {
        "clusters": clusters, "kind": kind, "intent": intent,
        "intents": INTENT_LABELS, "nav": "clusters",
    })


def cluster_detail(request, cid):
    db = _db()
    c = db.clusters.find_one({"_id": cid})
    if not c:
        raise Http404("no such cluster")
    recent = list(db.sessions.find({"cluster_id": cid}).sort("start", -1).limit(25))
    for s in recent:
        s["sid"] = s["_id"]
    downloads = list(db.sessions.aggregate([
        {"$match": {"cluster_id": cid}},
        {"$unwind": "$downloads"},
        {"$group": {"_id": "$downloads.url", "sha256": {"$first": "$downloads.sha256"}, "n": {"$sum": 1}}},
        {"$sort": {"n": -1}}, {"$limit": 15},
    ]))
    commands = c.get("sample_commands")
    if not commands:
        sample = db.sessions.find_one({"_id": c.get("sample_session")}) or {}
        commands = [x["input"] for x in sample.get("commands", [])]
    return render(request, "web/cluster_detail.html", {
        "c": c, "a": c.get("analysis") or {}, "commands": commands,
        "normalized": c.get("normalized", []), "recent": recent, "downloads": downloads,
        "ip_count": len(c.get("src_ips", [])), "nav": "clusters",
    })


def attack_matrix(request):
    db = _db()
    clusters = list(db.clusters.find({"analysis": {"$exists": True}},
                                     {"analysis": 1, "session_count": 1}))
    hits = _technique_counts(clusters)
    top = max((h["sessions"] for h in hits.values()), default=1) or 1
    columns = []
    for tactic in mitre.TACTIC_ORDER:
        cells = []
        for tid, (name, tac) in mitre.TECHNIQUES.items():
            if tac != tactic:
                continue
            h = hits.get(tid)
            # sequential blue: more sessions -> darker step
            level = 0 if not h else min(4, 1 + int(4 * h["sessions"] / (top + 1)))
            cells.append({"id": tid, "name": name, "url": mitre.url_for(tid),
                          "sessions": h["sessions"] if h else 0,
                          "clusters": h["clusters"] if h else 0, "level": level})
        cells.sort(key=lambda x: -x["sessions"])
        columns.append({"tactic": tactic, "cells": cells,
                        "hit": sum(1 for x in cells if x["sessions"])})
    rejected = sum(len((c.get("analysis") or {}).get("rejected_techniques", [])) for c in clusters)
    return render(request, "web/attack.html", {
        "columns": columns, "observed": len(hits), "total": len(mitre.TECHNIQUES),
        "rejected": rejected, "nav": "attack",
    })
