import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(override=True)

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "nids.db"
STATIC_DIR = BASE_DIR / "static"

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
DEMO_MODE = os.environ.get("NIDS_DEMO", "").lower() in ("1", "true", "yes")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
AI_ENABLED = bool(ANTHROPIC_API_KEY)
