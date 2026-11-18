"""All settings come from environment variables (see .env.example)."""
import os

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "honeylens")

# Comma-separated glob patterns of Cowrie JSON log files to read.
LOG_GLOBS = [
    g.strip()
    for g in os.getenv("LOG_GLOBS", "./demo-logs/*.json").split(",")
    if g.strip()
]

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
LLM_MAX_CALLS_PER_CYCLE = int(os.getenv("LLM_MAX_CALLS_PER_CYCLE", "10"))

WORKER_INTERVAL_SECONDS = int(os.getenv("WORKER_INTERVAL_SECONDS", "60"))

# A session that never sent "closed" is treated as finished after this long.
STALE_SESSION_MINUTES = int(os.getenv("STALE_SESSION_MINUTES", "30"))
