"""Delete everything in the HoneyLens database (e.g. after testing with demo data).

    docker compose run --rm worker python -m honeylens.reset --yes
"""
import glob
import os
import sys

from .db import get_db

if __name__ == "__main__":
    if "--yes" not in sys.argv:
        sys.exit("This wipes the database. Re-run with --yes to confirm.")
    db = get_db()
    for name in ("logins", "sessions", "clusters", "ingest_state"):
        db[name].drop()
    for f in glob.glob("/demo-logs/*.json"):
        os.remove(f)
    print("database wiped and demo logs removed")
