from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class EndpointConfig:
    name: str
    host: str
    port: int
    username: str
    password: str
    wan_interface: Optional[str] = None
    display_index: int = 0


@dataclass(frozen=True)
class WireGuardPairConfig:
    client_wireguard_name: str
    server_wireguard_name: str
    wg_subnet: str
    client_wireguard_id: Optional[str] = None
    client_peers_id: Optional[str] = None
    server_wireguard_id: Optional[str] = None
    server_peers_id: Optional[str] = None
    server_ping_ip: Optional[str] = None


@dataclass(frozen=True)
class RouterLinkConfig:
    name: str
    client_endpoint_ref: str
    server_endpoint_ref: str
    wireguard: WireGuardPairConfig
    ping_count: int = 5
    packet_loss_threshold: int = 100
    repair_cooldown_seconds: int = 180
    repair_max_retries: int = 2


@dataclass(frozen=True)
class AppConfig:
    poll_interval_seconds: int
    max_workers: int
    connect_timeout_seconds: float
    command_timeout_seconds: float
    recheck_delay_seconds: int
    heartbeat_file: str
    log_level: str
    links: list[RouterLinkConfig]
    endpoints: dict[str, EndpointConfig]


@dataclass(frozen=True)
class HealthResult:
    router_name: str
    reachable: bool
    packet_loss: Optional[int]
    reason: str
