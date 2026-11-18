import os
import subprocess
import sys

import mongomock
import pytest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dashboard.settings")
os.environ["DJANGO_ALLOWED_HOSTS"] = "testserver,localhost"
import django  # noqa: E402

django.setup()
from django.test import Client  # noqa: E402

from honeylens import analyze, ingest  # noqa: E402
from honeylens.llm import RuleAnalyzer  # noqa: E402


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    db = mongomock.MongoClient(tz_aware=True)["dash"]
    out = tmp_path_factory.mktemp("logs") / "demo.json"
    subprocess.run([sys.executable, "-m", "honeylens.seed_demo", "--out", str(out), "--sessions", "400"],
                   check=True, capture_output=True)
    ingest.ingest_file(db, str(out))
    analyze.cluster_sessions(db)
    analyze.analyze_clusters(db, RuleAnalyzer(), max_calls=50)

    import web.views
    original = web.views._db
    web.views._db = lambda: db
    yield Client(), db
    web.views._db = original


@pytest.mark.parametrize("url", ["/", "/clusters/", "/clusters/?kind=all", "/clusters/?kind=commands&intent=cryptomining", "/attack/"])
def test_pages_render(client, url):
    c, _ = client
    r = c.get(url)
    assert r.status_code == 200, r.content[:500]


def test_cluster_detail_and_escaping(client):
    c, db = client
    cl = db.clusters.find_one({"kind": "commands"})
    r = c.get(f"/clusters/{cl['_id']}/")
    assert r.status_code == 200
    # attacker input is shown escaped, never as raw HTML
    db.sessions.update_one({"_id": cl["sample_session"]},
                           {"$push": {"commands": {"input": "<script>alert(1)</script>"}}})
    db.clusters.update_one({"_id": cl["_id"]}, {"$unset": {"sample_commands": 1}})
    r = c.get(f"/clusters/{cl['_id']}/")
    assert b"<script>alert(1)" not in r.content
    assert b"&lt;script&gt;" in r.content
    assert c.get("/clusters/nope/").status_code == 404
