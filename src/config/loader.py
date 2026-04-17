from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import yaml

from src.config.models import (
    AppConfig,
    EndpointConfig,
    RouterLinkConfig,
    WireGuardPairConfig,
)


class ConfigError(ValueError):
    pass


def _require(mapping: dict[str, Any], key: str) -> Any:
    if key not in mapping:
        raise ConfigError(f"Missing required field: {key}")
    return mapping[key]


def load_app_config(config_path: str) -> AppConfig:
    path = Path(config_path)
    if not path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    settings = raw.get("settings", {})
    if not isinstance(settings, dict):
        settings = {}
    endpoints = _parse_endpoints(raw.get("endpoints", {}))
    links = _parse_links(raw.get("links", []), endpoints)

    return AppConfig(
        poll_interval_seconds=int(settings.get("poll_interval_seconds", 60)),
        max_workers=int(settings.get("max_workers", 20)),
        connect_timeout_seconds=float(settings.get("connect_timeout_seconds", 8)),
        command_timeout_seconds=float(settings.get("command_timeout_seconds", 10)),
        recheck_delay_seconds=int(settings.get("recheck_delay_seconds", 10)),
        heartbeat_file=str(settings.get("heartbeat_file", "/tmp/mikrotik_monitor.heartbeat")),
        log_level=str(settings.get("log_level", "INFO")),
        links=links,
        endpoints=endpoints,
    )


def resolve_password(password: str) -> str:
    if not password:
        raise ConfigError("endpoint password is required")
    return password


def _parse_endpoints(raw_endpoints: dict[str, Any]) -> dict[str, EndpointConfig]:
    if not raw_endpoints:
        raise ConfigError("endpoints section is empty")
    result: dict[str, EndpointConfig] = {}
    for key, value in raw_endpoints.items():
        if not isinstance(value, dict):
            raise ConfigError(f"endpoints.{key} must be object")
        username = value.get("username")
        password = value.get("password")
        if not username:
            raise ConfigError(f"endpoints.{key}.username is required")
        if not password:
            raise ConfigError(f"endpoints.{key}.password is required")
        di_raw = value.get("display_index", value.get("index", 0))
        try:
            display_index = int(di_raw if di_raw is not None and di_raw != "" else 0)
        except (TypeError, ValueError):
            display_index = 0
        result[key] = EndpointConfig(
            name=key,
            host=str(_require(value, "host")),
            port=int(_require(value, "port")),
            username=str(username),
            password=str(password),
            wan_interface=str(value.get("wan_interface", "")).strip() or None,
            display_index=display_index,
        )
    return result


def _parse_links(raw_links: list[dict[str, Any]], endpoints: dict[str, EndpointConfig]) -> list[RouterLinkConfig]:
    if not raw_links:
        return []
    links: list[RouterLinkConfig] = []
    for item in raw_links:
        if not isinstance(item, dict):
            raise ConfigError("links item must be object")
        name = str(_require(item, "name"))
        client_endpoint_ref = str(_require(item, "client_endpoint_ref"))
        server_endpoint_ref = str(_require(item, "server_endpoint_ref"))
        if client_endpoint_ref not in endpoints:
            raise ConfigError(f"links.{name}.client_endpoint_ref does not exist")
        if server_endpoint_ref not in endpoints:
            raise ConfigError(f"links.{name}.server_endpoint_ref does not exist")
        wg = _require(item, "wireguard")
        if not isinstance(wg, dict):
            raise ConfigError(f"links.{name}.wireguard must be object")
        client_wireguard_name = str(wg.get("client_wireguard_name", "")).strip()
        server_wireguard_name = str(wg.get("server_wireguard_name", "")).strip()
        wg_subnet = str(wg.get("wg_subnet", "")).strip()
        if not client_wireguard_name:
            # backward compatibility
            client_wireguard_name = str(wg.get("client_wireguard_id", "")).strip()
        if not server_wireguard_name:
            server_wireguard_name = str(wg.get("server_wireguard_id", "")).strip()
        if not wg_subnet:
            # backward compatibility
            old_server_ip = str(wg.get("server_ip", "")).strip()
            if old_server_ip:
                wg_subnet = f"{old_server_ip}/32"
        if not client_wireguard_name or not server_wireguard_name:
            raise ConfigError(f"links.{name}.wireguard name fields are required")
        if not wg_subnet:
            raise ConfigError(f"links.{name}.wireguard.wg_subnet is required")
        wireguard = WireGuardPairConfig(
            client_wireguard_name=client_wireguard_name,
            server_wireguard_name=server_wireguard_name,
            wg_subnet=wg_subnet,
            client_wireguard_id=str(wg.get("client_wireguard_id", "")).strip() or None,
            client_peers_id=str(wg.get("client_peers_id", "")).strip() or None,
            server_wireguard_id=str(wg.get("server_wireguard_id", "")).strip() or None,
            server_peers_id=str(wg.get("server_peers_id", "")).strip() or None,
            server_ping_ip=str(wg.get("server_ping_ip", "")).strip() or _derive_ping_ip(wg_subnet),
        )
        links.append(
            RouterLinkConfig(
                name=name,
                client_endpoint_ref=client_endpoint_ref,
                server_endpoint_ref=server_endpoint_ref,
                wireguard=wireguard,
                ping_count=int(item.get("ping_count", 5)),
                packet_loss_threshold=int(item.get("packet_loss_threshold", 100)),
                repair_cooldown_seconds=int(item.get("repair_cooldown_seconds", 180)),
                repair_max_retries=int(item.get("repair_max_retries", 2)),
            )
        )
    return links


def _derive_ping_ip(wg_subnet: str) -> str | None:
    try:
        network = ipaddress.ip_network(wg_subnet, strict=False)
        first_host = next(network.hosts(), None)
        if first_host is not None:
            return str(first_host)
        return str(network.network_address)
    except ValueError:
        return None
