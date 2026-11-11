from __future__ import annotations

from .compat import HOSTFAKESPLIT_INIT
from .config_format import (
    ConfigFormatError,
    assignment as _format_assignment,
    replace_assignment,
    replace_scalar,
)


class HybridConfigError(RuntimeError):
    """The stock or converted configuration cannot be merged safely."""


def _assignment(config: str, name: str):
    """Compatibility wrapper that raises HybridConfigError on bad input."""
    try:
        return _format_assignment(config, name)
    except ConfigFormatError as error:
        raise HybridConfigError(str(error)) from error


def _lines(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


def _replace(config: str, name: str, lines: list[str]) -> str:
    return replace_assignment(config, name, lines)


def _value(config: str, name: str) -> str | None:
    """Return an assignment value, or None when an older config lacks it."""
    try:
        return _assignment(config, name).value
    except HybridConfigError:
        return None


def _replace_value(config: str, name: str, value: str, *, quoted: bool) -> str:
    """Replace a scalar assignment while keeping the rest of the file intact."""
    return replace_scalar(config, name, value, quoted=quoted)


def _port_tokens(value: str) -> list[str]:
    return [token.strip() for token in value.split(",") if token.strip()]


def _merge_ports(stock_value: str, converted_value: str) -> str:
    """Union ports because iptables decides which traffic reaches nfqws2.

    Stock TCP_PORTS/UDP_PORTS describe the package's own strategies. Custom
    Flowseal profiles may filter ports outside that set, so keeping only the
    stock list would silently drop their traffic.
    """
    merged: list[str] = []
    seen: set[str] = set()
    for token in (*_port_tokens(stock_value), *_port_tokens(converted_value)):
        key = token.replace("-", ":")
        if key not in seen:
            seen.add(key)
            merged.append(token)
    return ",".join(merged)


def _profiles(value: str) -> list[list[str]]:
    result: list[list[str]] = []
    current: list[str] = []
    for line in _lines(value):
        if line == "--new":
            if current:
                result.append(current)
                current = []
        else:
            current.append(line)
    if current:
        result.append(current)
    return result


def _is_discord_profile(profile: list[str]) -> bool:
    text = "\n".join(profile).lower()
    return any(
        marker in text
        for marker in (
            "/lists/list-general.",
            "--filter-l7=discord,stun",
            "--hostlist-domains=discord.media",
        )
    )


def build_hybrid_keenetic_config(stock_config: str, converted_config: str) -> str:
    """Merge Flowseal's Discord profiles with nfqws2's adaptive stock strategy.

    Discord-specific profiles are placed in NFQWS_ARGS_CUSTOM, which the package
    starts before its generic UDP/QUIC/TCP profiles. YouTube and other entries in
    the package lists therefore keep using nfqws2's adaptive strategy.
    """
    stock_base = _lines(_assignment(stock_config, "NFQWS_BASE_ARGS").value)
    converted_base = _lines(_assignment(converted_config, "NFQWS_BASE_ARGS").value)
    inline_blobs = [line for line in converted_base if line.startswith("--blob=")]
    known_blob_names = {line.split(":", 1)[0] for line in stock_base if line.startswith("--blob=")}
    for declaration in inline_blobs:
        if declaration.split(":", 1)[0] not in known_blob_names:
            stock_base.append(declaration)
    if HOSTFAKESPLIT_INIT in converted_base and HOSTFAKESPLIT_INIT not in stock_base:
        stock_base.append(HOSTFAKESPLIT_INIT)

    converted_profiles = _profiles(_assignment(converted_config, "NFQWS_ARGS_CUSTOM").value)
    converted_profiles.append(_lines(_assignment(converted_config, "NFQWS_ARGS").value))
    discord_profiles = [profile for profile in converted_profiles if _is_discord_profile(profile)]
    if not discord_profiles:
        raise HybridConfigError("В конвертированном профиле не найдены стратегии Discord")

    custom: list[str] = []
    for index, profile in enumerate(discord_profiles):
        if index:
            custom.append("--new")
        custom.extend(profile)

    ipset_args = _lines(_assignment(stock_config, "NFQWS_ARGS_IPSET").value)
    ipset_all = "--ipset=/opt/etc/nfqws2/lists/ipset-all.list"
    if ipset_all not in ipset_args:
        insert_at = next((i for i, line in enumerate(ipset_args) if line.startswith("--ipset-exclude=")), len(ipset_args))
        ipset_args.insert(insert_at, ipset_all)

    result = stock_config
    result = _replace(result, "NFQWS_BASE_ARGS", stock_base)
    result = _replace(result, "NFQWS_ARGS_IPSET", ipset_args)
    result = _replace(result, "NFQWS_ARGS_CUSTOM", custom)

    # The stock config is only the strategy base. Network settings selected by
    # the user in the converter must still be applied, otherwise hybrid mode
    # silently installs the wrong interface, policy or IPv6 mode.
    for name, quoted in (
        ("ISP_INTERFACE", True),
        ("IPV6_ENABLED", False),
        ("POLICY_NAME", True),
        ("POLICY_EXCLUDE", False),
        ("NFQUEUE_NUM", False),
    ):
        value = _value(converted_config, name)
        if value is not None:
            result = _replace_value(result, name, value, quoted=quoted)

    for name in ("TCP_PORTS", "UDP_PORTS"):
        stock_ports = _value(stock_config, name)
        converted_ports = _value(converted_config, name)
        if stock_ports is not None and converted_ports is not None:
            result = _replace_value(
                result,
                name,
                _merge_ports(stock_ports, converted_ports),
                quoted=False,
            )

    header = (
        "# Hybrid configuration generated by zapret-keenetic-converter.\n"
        "# Discord/general: selected Flowseal profiles; other traffic: nfqws2 adaptive strategy.\n"
        "# Network settings (interface, IPv6, policy, queue, ports) come from the converter.\n"
    )
    return header + result.lstrip("\ufeff")
