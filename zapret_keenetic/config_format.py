"""Read and write the nfqws2 shell-style configuration format.

Both the exact converter and the hybrid merger use the same helpers. The file
is sourced by the package init script, so values are shell strings; helpers in
this module keep quoting and replacement consistent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence


class ConfigFormatError(RuntimeError):
    """An assignment cannot be parsed or is missing."""


@dataclass(frozen=True)
class Assignment:
    start: int
    end: int
    value: str


def assignment(config: str, name: str) -> Assignment:
    match = re.search(rf"(?m)^{re.escape(name)}=", config)
    if not match:
        raise ConfigFormatError(f"В конфигурации отсутствует параметр {name}")

    value_start = match.end()
    if value_start >= len(config):
        return Assignment(match.start(), value_start, "")

    quote = config[value_start]
    if quote not in {'"', "'"}:
        line_end = config.find("\n", value_start)
        if line_end < 0:
            line_end = len(config)
        return Assignment(match.start(), line_end, config[value_start:line_end].strip())

    cursor = value_start + 1
    escaped = False
    while cursor < len(config):
        character = config[cursor]
        if quote == '"' and escaped:
            escaped = False
        elif quote == '"' and character == "\\":
            escaped = True
        elif character == quote:
            raw = config[value_start + 1 : cursor]
            if quote == '"':
                raw = re.sub(r"\\([\\\"$`])", r"\1", raw)
            else:
                raw = raw.replace("'\\''", "'")
            return Assignment(match.start(), cursor + 1, raw)
        cursor += 1
    raise ConfigFormatError(f"Незакрытая строка параметра {name}")


def config_value(lines: Sequence[str], indent: int = 17) -> str:
    if not lines:
        return '""'
    padding = " " * indent
    escaped = [
        line.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
        for line in lines
    ]
    return '"' + ("\n" + padding).join(escaped) + '"'


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def replace_assignment(config: str, name: str, lines: Sequence[str]) -> str:
    current = assignment(config, name)
    replacement = f"{name}={config_value(lines)}"
    return config[: current.start] + replacement + config[current.end :]


def replace_scalar(config: str, name: str, value: str, *, quoted: bool) -> str:
    """Replace a scalar assignment, leaving older configs without it untouched."""
    try:
        current = assignment(config, name)
    except ConfigFormatError:
        return config
    replacement = f"{name}={config_value([value]) if quoted else value}"
    return config[: current.start] + replacement + config[current.end :]
