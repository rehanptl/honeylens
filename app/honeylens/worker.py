"""Background loop: ingest logs -> cluster sessions -> explain new clusters. Repeat."""
import logging
import time

from . import config
from .analyze import analyze_clusters, cluster_sessions
from .db import ensure_indexes, get_db
from .ingest import ingest_all
from .llm import get_analyzer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("honeylens.worker")


def run_once(db, analyzer) -> dict:
    stats = {
        "events": ingest_all(db, config.LOG_GLOBS),
        "clustered": cluster_sessions(db),
        "analyzed": analyze_clusters(db, analyzer, config.LLM_MAX_CALLS_PER_CYCLE),
    }
    return stats


def main():
    db = get_db()
    ensure_indexes(db)
    analyzer = get_analyzer()
    log.info("worker started (analyzer=%s, logs=%s)", analyzer.source, config.LOG_GLOBS)
    while True:
        try:
            stats = run_once(db, analyzer)
            if any(stats.values()):
                log.info("cycle: %s", stats)
        except Exception:
            log.exception("cycle failed; retrying next interval")
        time.sleep(config.WORKER_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
