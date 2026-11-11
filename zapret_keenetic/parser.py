"""Parse Flowseal ``.bat`` profiles into winws option groups."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .errors import ConversionError


@dataclass(frozen=True)
class Option:
    name: str
    value: str | None


OPTION_RE = re.compile(
    r"--(?P<name>[A-Za-z0-9][A-Za-z0-9-]*)(?:=(?P<value>\"[^\"]*\"|[^\s]+))?"
)
WINWS_RE = re.compile(r"winws(?:\.exe)?\"?", re.IGNORECASE)
VAR_RE = re.compile(r"%([^%]+)%", re.IGNORECASE)


def read_batch(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-8-sig", "cp1251", "utf-8"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ConversionError(f"Не удалось определить кодировку файла: {path}")


def parse_batch(path: Path) -> tuple[list[Option], list[list[Option]]]:
    text = read_batch(path).replace("\r\n", "\n")
    text = re.sub(r"\^\s*\n", " ", text)
    match = WINWS_RE.search(text)
    if not match:
        raise ConversionError(f"В {path.name} не найден запуск winws.exe")
    command = text[match.end() :]
    options: list[Option] = []
    for item in OPTION_RE.finditer(command):
        value = item.group("value")
        if value is not None:
            value = value.strip('"')
            if value.startswith("^"):
                value = value[1:]
            value = value.rstrip("^")
        options.append(Option(item.group("name").lower(), value))
    if not options:
        raise ConversionError(f"В команде winws файла {path.name} не найдены параметры")

    global_options: list[Option] = []
    profiles: list[list[Option]] = [[]]
    seen_profile = False
    for option in options:
        if option.name == "new":
            seen_profile = True
            if profiles[-1]:
                profiles.append([])
            continue
        if option.name.startswith("wf-") and not seen_profile:
            global_options.append(option)
        else:
            seen_profile = True
            profiles[-1].append(option)
    profiles = [profile for profile in profiles if profile]
    return global_options, profiles
