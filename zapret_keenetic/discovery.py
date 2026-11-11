"""Locate a Flowseal installation without scanning the whole disk."""
from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from .errors import ConversionError
from .parser import parse_batch


def discover_profiles(source: Path) -> list[str]:
    """Find real winws profiles and return source-relative paths."""
    if not source.is_dir():
        return []
    profiles: list[str] = []
    for candidate in source.rglob("*.bat"):
        if any(part.lower() in {".git", "bin"} for part in candidate.relative_to(source).parts[:-1]):
            continue
        try:
            _, parsed = parse_batch(candidate)
        except (ConversionError, OSError):
            continue
        if any(option.name == "dpi-desync" and option.value for profile in parsed for option in profile):
            profiles.append(candidate.relative_to(source).as_posix())
    return sorted(profiles, key=lambda value: ("general" not in value.lower(), value.lower()))


def suggest_output(source: Path, profile: str, target: str, moment: datetime | None = None) -> Path:
    stamp = (moment or datetime.now()).strftime("%Y%m%d-%H%M%S")
    stem = Path(profile).stem
    safe_stem = re.sub(r"[^0-9A-Za-zА-Яа-яЁё_-]+", "-", stem).strip("-").lower() or "profile"
    parent = source.parent / "KeeneticZapret-converted"
    candidate = parent / f"{safe_stem}-{target}-{stamp}"
    suffix = 2
    while candidate.exists():
        candidate = parent / f"{safe_stem}-{target}-{stamp}-{suffix}"
        suffix += 1
    return candidate


def has_profiles(path: Path) -> bool:
    """Return True if the directory contains at least one usable winws profile."""
    if not path.is_dir():
        return False
    try:
        candidates = sorted(path.glob("*.bat"))
    except OSError:
        return False
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            _, profiles = parse_batch(candidate)
        except (ConversionError, OSError):
            continue
        if any(option.name == "dpi-desync" and option.value for profile in profiles for option in profile):
            return True
    return False


def _candidate_roots(home: Path | None = None) -> list[Path]:
    home = home or Path.home()
    roots = [Path.cwd(), Path(sys.executable).resolve().parent]
    roots.extend((home / "Downloads", home / "Desktop", home))
    unique: list[Path] = []
    for root in roots:
        if root not in unique:
            unique.append(root)
    return unique


def find_flowseal_source(
    roots: Iterable[Path] | None = None,
    home: Path | None = None,
) -> Path | None:
    """Find a nearby Flowseal folder, preferring an explicit FLOWSEAL_DIR."""
    override = os.environ.get("FLOWSEAL_DIR")
    if override:
        candidate = Path(override).expanduser()
        if has_profiles(candidate):
            return candidate

    for root in roots if roots is not None else _candidate_roots(home):
        candidate = Path(root).expanduser()
        if has_profiles(candidate):
            return candidate
        if not candidate.is_dir():
            continue
        try:
            children = sorted(candidate.iterdir())
        except OSError:
            continue
        for child in children[:200]:
            if not child.is_dir() or child.name.startswith("."):
                continue
            lowered = child.name.lower()
            if not any(marker in lowered for marker in ("zapret", "flowseal", "discord")):
                continue
            if has_profiles(child):
                return child
    return None
