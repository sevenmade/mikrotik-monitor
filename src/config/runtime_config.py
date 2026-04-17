from __future__ import annotations

import threading
import secrets
from pathlib import Path
from typing import Any

import yaml


def _to_int(value: Any, default: int) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


class RuntimeConfigStore:
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self._lock = threading.Lock()

    def read_raw(self) -> dict[str, Any]:
        with self._lock:
            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        return raw

    def ensure_web_password(self) -> tuple[str, bool]:
        with self._lock:
            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
            settings = raw.get("settings", {})
            if not isinstance(settings, dict):
                settings = {}
                raw["settings"] = settings
            current = str(settings.get("web_password", "")).strip()
            if current:
                return current, False
            generated = secrets.token_urlsafe(12)
            settings["web_password"] = generated
            self.config_path.write_text(yaml.safe_dump(raw, allow_unicode=True, sort_keys=False), encoding="utf-8")
            return generated, True

    def get_settings(self) -> dict[str, Any]:
        raw = self.read_raw()
        settings = raw.get("settings", {})
        if not isinstance(settings, dict):
            settings = {}
        return {
            "poll_interval_seconds": _to_int(settings.get("poll_interval_seconds", 60), 60),
            "max_workers": _to_int(settings.get("max_workers", 20), 20),
            "connect_timeout_seconds": _to_int(settings.get("connect_timeout_seconds", 8), 8),
            "command_timeout_seconds": _to_int(settings.get("command_timeout_seconds", 10), 10),
            "recheck_delay_seconds": _to_int(settings.get("recheck_delay_seconds", 10), 10),
            "heartbeat_file": str(settings.get("heartbeat_file", "/tmp/mikrotik_monitor.heartbeat")),
            "log_level": str(settings.get("log_level", "INFO")),
            "web_password": str(settings.get("web_password", "")),
        }

    def update_settings(self, payload: dict[str, Any]) -> None:
        with self._lock:
            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
            settings = raw.get("settings", {})
            if not isinstance(settings, dict):
                settings = {}
                raw["settings"] = settings
            for key in (
                "poll_interval_seconds",
                "max_workers",
                "connect_timeout_seconds",
                "command_timeout_seconds",
                "recheck_delay_seconds",
            ):
                if key in payload:
                    settings[key] = _to_int(payload.get(key), _to_int(settings.get(key), 0))
            if "heartbeat_file" in payload:
                settings["heartbeat_file"] = str(payload.get("heartbeat_file", "")).strip()
            if "log_level" in payload:
                settings["log_level"] = str(payload.get("log_level", "INFO")).strip().upper()
            if "web_password" in payload:
                settings["web_password"] = str(payload.get("web_password", "")).strip()
            self.config_path.write_text(yaml.safe_dump(raw, allow_unicode=True, sort_keys=False), encoding="utf-8")

    def read_yaml_text(self) -> str:
        with self._lock:
            return self.config_path.read_text(encoding="utf-8")

    def write_yaml_text(self, text: str) -> None:
        parsed = yaml.safe_load(text) or {}
        if not isinstance(parsed, dict):
            raise ValueError("YAML 顶层必须是对象")
        with self._lock:
            self.config_path.write_text(text, encoding="utf-8")

    def list_endpoints(self) -> list[dict[str, Any]]:
        raw = self.read_raw()
        endpoints = raw.get("endpoints", {})
        if not isinstance(endpoints, dict):
            return []
        rows: list[dict[str, Any]] = []
        for name, item in endpoints.items():
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "name": name,
                    "host": str(item.get("host", "")),
                    "port": _to_int(item.get("port", 0), 0),
                    "username": str(item.get("username", "")),
                    "password": str(item.get("password", "")),
                    "wan_interface": str(item.get("wan_interface", "")),
                    "display_index": _to_int(item.get("display_index", item.get("index", 0)), 0),
                }
            )
        rows.sort(key=lambda x: (x["display_index"], x["name"]))
        return rows

    def upsert_endpoint(self, payload: dict[str, Any]) -> None:
        name = str(payload.get("name", "")).strip()
        if not name:
            raise ValueError("name is required")
        with self._lock:
            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
            endpoints = raw.setdefault("endpoints", {})
            if not isinstance(endpoints, dict):
                endpoints = {}
                raw["endpoints"] = endpoints
            current = endpoints.get(name, {}) if isinstance(endpoints.get(name), dict) else {}
            current["host"] = str(payload.get("host", current.get("host", ""))).strip()
            current["port"] = _to_int(payload.get("port", current.get("port", 0)), 0)
            current["username"] = str(payload.get("username", current.get("username", ""))).strip()
            current["password"] = str(payload.get("password", current.get("password", ""))).strip()
            current["wan_interface"] = str(payload.get("wan_interface", current.get("wan_interface", ""))).strip()
            di_src = payload.get("display_index", current.get("display_index", current.get("index", 0)))
            current["display_index"] = _to_int(di_src, 0)
            current.pop("index", None)
            endpoints[name] = current
            self.config_path.write_text(yaml.safe_dump(raw, allow_unicode=True, sort_keys=False), encoding="utf-8")

    def delete_endpoint(self, name: str) -> None:
        endpoint_name = name.strip()
        if not endpoint_name:
            raise ValueError("name is required")
        with self._lock:
            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
            endpoints = raw.get("endpoints", {})
            if isinstance(endpoints, dict) and endpoint_name in endpoints:
                endpoints.pop(endpoint_name, None)
            links = raw.get("links", [])
            if not isinstance(links, list):
                links = []
            filtered = []
            for item in links:
                if not isinstance(item, dict):
                    continue
                if item.get("client_endpoint_ref") == endpoint_name:
                    continue
                if item.get("server_endpoint_ref") == endpoint_name:
                    continue
                filtered.append(item)
            raw["links"] = filtered
            self.config_path.write_text(yaml.safe_dump(raw, allow_unicode=True, sort_keys=False), encoding="utf-8")

    def list_links(self) -> list[dict[str, Any]]:
        raw = self.read_raw()
        links = raw.get("links", [])
        if not isinstance(links, list):
            links = []
        rows: list[dict[str, Any]] = []
        for item in links:
            if not isinstance(item, dict):
                continue
            wg = item.get("wireguard", {}) if isinstance(item.get("wireguard"), dict) else {}
            rows.append(
                {
                    "name": str(item.get("name", "")),
                    "server_endpoint_ref": str(item.get("server_endpoint_ref", "")),
                    "client_endpoint_ref": str(item.get("client_endpoint_ref", "")),
                    "server_wireguard_name": str(wg.get("server_wireguard_name", "")),
                    "client_wireguard_name": str(wg.get("client_wireguard_name", "")),
                    "wg_subnet": str(wg.get("wg_subnet", "")),
                    "server_ping_ip": str(wg.get("server_ping_ip", "")),
                    "ping_count": _to_int(item.get("ping_count", 5), 5),
                    "packet_loss_threshold": _to_int(item.get("packet_loss_threshold", 100), 100),
                    "repair_cooldown_seconds": _to_int(item.get("repair_cooldown_seconds", 180), 180),
                    "repair_max_retries": _to_int(item.get("repair_max_retries", 2), 2),
                }
            )
        rows.sort(key=lambda x: x["name"])
        return rows

    def upsert_link(self, payload: dict[str, Any]) -> None:
        name = str(payload.get("name", "")).strip()
        if not name:
            raise ValueError("link name is required")
        with self._lock:
            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
            endpoints = raw.get("endpoints", {})
            client_ref = str(payload.get("client_endpoint_ref", "")).strip()
            server_ref = str(payload.get("server_endpoint_ref", "")).strip()
            client = endpoints.get(client_ref, {}) if isinstance(endpoints, dict) else {}
            server = endpoints.get(server_ref, {}) if isinstance(endpoints, dict) else {}
            if not client_ref or not isinstance(client, dict):
                raise ValueError("client_endpoint_ref 不存在")
            if not server_ref or not isinstance(server, dict):
                raise ValueError("server_endpoint_ref 不存在")
            links = raw.setdefault("links", [])
            if not isinstance(links, list):
                links = []
                raw["links"] = links
            replaced = False
            for idx, item in enumerate(links):
                if isinstance(item, dict) and str(item.get("name", "")) == name:
                    links[idx] = self._build_link_payload(payload, item)
                    replaced = True
                    break
            if not replaced:
                links.append(self._build_link_payload(payload, {}))
            self.config_path.write_text(yaml.safe_dump(raw, allow_unicode=True, sort_keys=False), encoding="utf-8")

    def delete_link(self, name: str) -> None:
        link_name = name.strip()
        if not link_name:
            raise ValueError("link name is required")
        with self._lock:
            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
            links = raw.get("links", [])
            if not isinstance(links, list):
                links = []
            raw["links"] = [item for item in links if not (isinstance(item, dict) and str(item.get("name", "")) == link_name)]
            self.config_path.write_text(yaml.safe_dump(raw, allow_unicode=True, sort_keys=False), encoding="utf-8")

    @staticmethod
    def _build_link_payload(payload: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
        current_wg = current.get("wireguard", {}) if isinstance(current.get("wireguard"), dict) else {}
        return {
            "name": str(payload.get("name", current.get("name", ""))).strip(),
            "client_endpoint_ref": str(payload.get("client_endpoint_ref", current.get("client_endpoint_ref", ""))).strip(),
            "server_endpoint_ref": str(payload.get("server_endpoint_ref", current.get("server_endpoint_ref", ""))).strip(),
            "ping_count": _to_int(payload.get("ping_count", current.get("ping_count", 5)), 5),
            "packet_loss_threshold": _to_int(payload.get("packet_loss_threshold", current.get("packet_loss_threshold", 100)), 100),
            "repair_cooldown_seconds": _to_int(payload.get("repair_cooldown_seconds", current.get("repair_cooldown_seconds", 180)), 180),
            "repair_max_retries": _to_int(payload.get("repair_max_retries", current.get("repair_max_retries", 2)), 2),
            "wireguard": {
                "client_wireguard_name": str(payload.get("client_wireguard_name", current_wg.get("client_wireguard_name", ""))).strip(),
                "server_wireguard_name": str(payload.get("server_wireguard_name", current_wg.get("server_wireguard_name", ""))).strip(),
                "wg_subnet": str(payload.get("wg_subnet", current_wg.get("wg_subnet", ""))).strip(),
                "server_ping_ip": str(payload.get("server_ping_ip", current_wg.get("server_ping_ip", ""))).strip(),
                # Optional advanced fallback fields:
                "client_wireguard_id": str(payload.get("client_wireguard_id", current_wg.get("client_wireguard_id", ""))).strip(),
                "client_peers_id": str(payload.get("client_peers_id", current_wg.get("client_peers_id", ""))).strip(),
                "server_wireguard_id": str(payload.get("server_wireguard_id", current_wg.get("server_wireguard_id", ""))).strip(),
                "server_peers_id": str(payload.get("server_peers_id", current_wg.get("server_peers_id", ""))).strip(),
            },
        }
