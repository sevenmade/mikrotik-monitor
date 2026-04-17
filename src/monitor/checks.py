from __future__ import annotations

from src.config.models import HealthResult, RouterLinkConfig
from src.routeros.client import RouterOsClient


def check_wireguard_reachability(client: RouterOsClient, link: RouterLinkConfig) -> HealthResult:
    ping_ip = link.wireguard.server_ping_ip
    if not ping_ip:
        return HealthResult(router_name=link.name, reachable=False, packet_loss=None, reason="missing server_ping_ip")
    target_address = f"=address={ping_ip}"
    count = f"=count={link.ping_count}"
    response = client.talk(["/ping", target_address, count])

    packet_loss = None
    for _, attrs in response:
        value = attrs.get("=packet-loss")
        if value is None:
            continue
        try:
            packet_loss = int(value)
        except ValueError:
            packet_loss = 100

    if packet_loss is None:
        return HealthResult(router_name=link.name, reachable=False, packet_loss=None, reason="missing packet-loss value")
    if packet_loss >= link.packet_loss_threshold:
        return HealthResult(
            router_name=link.name,
            reachable=False,
            packet_loss=packet_loss,
            reason=f"packet-loss {packet_loss}% >= {link.packet_loss_threshold}%",
        )
    return HealthResult(router_name=link.name, reachable=True, packet_loss=packet_loss, reason="reachable")


def sample_wireguard_rate_bps(client: RouterOsClient, link: RouterLinkConfig) -> tuple[float, float]:
    interface_name = link.wireguard.client_wireguard_name
    if not interface_name:
        interface_name = _resolve_interface_name(client, link.wireguard.client_wireguard_id or "")
    if not interface_name:
        return 0.0, 0.0
    response = client.talk(
        [
            "/interface/monitor-traffic",
            f"=interface={interface_name}",
            "=once=",
        ]
    )
    tx_bps = 0.0
    rx_bps = 0.0
    for _, attrs in response:
        tx_bps = _to_float(attrs.get("=tx-bits-per-second") or attrs.get("=tx-bps") or attrs.get("=tx-byte"))
        rx_bps = _to_float(attrs.get("=rx-bits-per-second") or attrs.get("=rx-bps") or attrs.get("=rx-byte"))
        if tx_bps > 0 or rx_bps > 0:
            break
    return tx_bps, rx_bps


def sample_wan_rate_bps(client: RouterOsClient, preferred_interface: str | None = None) -> tuple[float, float, str]:
    interface_name = preferred_interface or _detect_wan_interface(client)
    if not interface_name:
        return 0.0, 0.0, ""
    response = client.talk(
        [
            "/interface/monitor-traffic",
            f"=interface={interface_name}",
            "=once=",
        ]
    )
    tx_bps = 0.0
    rx_bps = 0.0
    for _, attrs in response:
        tx_bps = _to_float(attrs.get("=tx-bits-per-second") or attrs.get("=tx-bps"))
        rx_bps = _to_float(attrs.get("=rx-bits-per-second") or attrs.get("=rx-bps"))
        if tx_bps > 0 or rx_bps > 0:
            break
    return tx_bps, rx_bps, interface_name


def _detect_wan_interface(client: RouterOsClient) -> str:
    rows = client.talk(["/interface/print", "?running=true"])
    candidates: list[str] = []
    for _, attrs in rows:
        name = attrs.get("=name", "")
        if not name:
            continue
        iface_type = attrs.get("=type", "")
        if iface_type in {"wireguard", "bridge"}:
            continue
        if name.startswith("wg") or name.startswith("bridge"):
            continue
        candidates.append(name)
    return candidates[0] if candidates else ""


def _resolve_interface_name(client: RouterOsClient, interface_id: str) -> str:
    if not interface_id:
        return ""
    rows = client.talk(["/interface/wireguard/print", f"=.id={interface_id}"])
    for _, attrs in rows:
        name = attrs.get("=name")
        if name:
            return name
    return ""


def _to_float(raw: str | None) -> float:
    if raw is None:
        return 0.0
    try:
        return float(raw)
    except ValueError:
        return 0.0
