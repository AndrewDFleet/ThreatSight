import os
from dotenv import load_dotenv

load_dotenv(override=True)

MODEL = "claude-opus-4-7"
MAX_TOKENS_ANALYSIS = 1024
MAX_TOKENS_REPORT = 4096

REQUESTS_PER_MINUTE = 20
REQUEST_TIMEOUT = 60.0
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2.0

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
