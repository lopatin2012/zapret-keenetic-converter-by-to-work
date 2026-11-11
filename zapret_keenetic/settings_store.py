"""Persist user preferences without storing secrets."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

APP_DIR = "ZapretKeeneticConverter"


def default_settings_path() -> Path:
    override = os.environ.get("ZAPRET_CONVERTER_SETTINGS")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / APP_DIR / "settings.json"


def load_settings(path: Path | None = None) -> dict[str, Any]:
    target = path or default_settings_path()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_settings(values: dict[str, Any], path: Path | None = None) -> Path:
    target = path or default_settings_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    try:
        temporary.write_text(
            json.dumps(values, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        temporary.replace(target)
    except OSError:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return target
