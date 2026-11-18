"""MongoDB connection + indexes.

Collections:
  logins        one doc per login attempt (username/password/ip/time)
  sessions      one doc per SSH connection, with every command typed
  clusters      one doc per *attack pattern*; many sessions -> one cluster
  ingest_state  how far into each log file we've read
"""
from pymongo import ASCENDING, DESCENDING, MongoClient

from . import config

_client = None


def get_db(client=None):
    global _client
    if client is not None:
        return client[config.MONGO_DB]
    if _client is None:
        _client = MongoClient(config.MONGO_URI, tz_aware=True)
    return _client[config.MONGO_DB]


def ensure_indexes(db):
    db.logins.create_index([("ts", DESCENDING)])
    db.logins.create_index([("src_ip", ASCENDING)])
    db.sessions.create_index([("clustered", ASCENDING), ("closed", ASCENDING)])
    db.sessions.create_index([("cluster_id", ASCENDING), ("start", DESCENDING)])
    db.sessions.create_index([("start", DESCENDING)])
    db.clusters.create_index([("session_count", DESCENDING)])
    db.clusters.create_index([("needs_analysis", ASCENDING)])
