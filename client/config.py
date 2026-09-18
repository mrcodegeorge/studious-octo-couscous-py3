import json
from pathlib import Path
from typing import Optional

CONFIG_FILE = Path(__file__).resolve().parent / "client_config.json"


def load_client_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "server_url": "http://127.0.0.1:8000",
        "device_uuid": None,
        "client_token": None,
        "hostname": None,
        "is_registered": False
    }


def save_client_config(config: dict):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def reset_client_config():
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
