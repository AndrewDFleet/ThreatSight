import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import threading
import time
import webbrowser
import uvicorn
import config


BANNER = r"""
  _____ _                    _   ____  _       _     _
 |_   _| |__  _ __ ___  __ _| |_/ ___|(_) __ _| |__ | |_
   | | | '_ \| '__/ _ \/ _` | __\___ \| |/ _` | '_ \| __|
   | | | | | | | |  __/ (_| | |_ ___) | | (_| | | | | |_
   |_| |_| |_|_|  \___|\__,_|\__|____/|_|\__, |_| |_|\__|
                                          |___/
"""


def print_startup():
    print(BANNER)
    print(f"  Mode    : {'DEMO  (simulated traffic)' if config.DEMO_MODE else 'LIVE  (real packet capture)'}")
    print(f"  AI      : {'Enabled  — Claude API connected' if config.AI_ENABLED else 'Disabled — set ANTHROPIC_API_KEY in .env'}")
    print(f"  URL     : http://{config.HOST}:{config.PORT}")
    print(f"  Database: {config.DB_PATH}")
    print()
    if not config.DEMO_MODE:
        print("  NOTE: Live capture requires Administrator / root privileges.")
        print("        Run as Administrator or set NIDS_DEMO=true in .env for demo mode.")
        print()
    if not config.AI_ENABLED:
        print("  WARNING: AI analysis is disabled. Add ANTHROPIC_API_KEY to .env to enable.")
        print()
    print("  Press Ctrl+C to stop.")
    print()


def _open_browser():
    time.sleep(2)
    webbrowser.open(f"http://{config.HOST}:{config.PORT}")


if __name__ == "__main__":
    print_startup()
    threading.Thread(target=_open_browser, daemon=True).start()
    uvicorn.run(
        "api.app:app",
        host=config.HOST,
        port=config.PORT,
        reload=False,
        log_level="warning",
    )
