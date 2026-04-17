from __future__ import annotations

from src.config.loader import ConfigError, resolve_password
from src.config.runtime_config import RuntimeConfigStore
from src.routeros.client import LoginInfo, RouterOsClient, RouterOsError


def list_wireguard_interface_names(
    config_store: RuntimeConfigStore,
    endpoint_name: str,
    connect_timeout: float = 8.0,
    command_timeout: float = 10.0,
) -> list[str]:
    """Return WireGuard interface names from the given configured endpoint (RouterOS)."""
    key = endpoint_name.strip()
    if not key:
        raise ValueError("缺少 endpoint 参数")
    raw = config_store.read_raw()
    endpoints = raw.get("endpoints", {})
    if not isinstance(endpoints, dict):
        raise ValueError("配置中无 endpoints")
    item = endpoints.get(key)
    if not isinstance(item, dict):
        raise ValueError("未知的路由器设备")
    host = str(item.get("host", "")).strip()
    port = int(item.get("port", 8728) or 8728)
    username = str(item.get("username", "")).strip()
    password = str(item.get("password", ""))
    if not host or not username:
        raise ValueError("该设备缺少 host 或 username")
    try:
        resolved_password = resolve_password(password)
    except ConfigError as exc:
        raise ValueError(str(exc)) from exc
    login = LoginInfo(host=host, port=port, username=username, password=resolved_password)
    names: list[str] = []
    with RouterOsClient(login, connect_timeout, command_timeout) as client:
        rows = client.talk(["/interface/wireguard/print"])
    for reply, attrs in rows:
        if reply != "!re":
            continue
        n = str(attrs.get("=name", "")).strip()
        if n:
            names.append(n)
    names.sort(key=lambda x: x.casefold())
    return names
