from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass

from src.config.models import AppConfig, RouterLinkConfig
from src.monitor.checks import check_wireguard_reachability
from src.routeros.client import LoginInfo, RouterOsClient


@dataclass
class RepairState:
    last_repair_ts: float = 0.0
    consecutive_failures: int = 0
    circuit_open_until: float = 0.0


class WireGuardHealer:
    def __init__(self, app_config: AppConfig):
        self.app_config = app_config
        self.logger = logging.getLogger(__name__)

    def attempt_repair(
        self,
        link: RouterLinkConfig,
        state: RepairState,
        client_login: LoginInfo,
        server_login: LoginInfo,
    ) -> bool:
        now = time.time()
        if now < state.circuit_open_until:
            self.logger.warning("circuit open, skip repair: %s", link.name)
            return False
        if now - state.last_repair_ts < link.repair_cooldown_seconds:
            self.logger.info("repair cooldown active for %s", link.name)
            return False

        for attempt in range(link.repair_max_retries):
            try:
                self._repair_once(link, client_login, server_login)
                time.sleep(self.app_config.recheck_delay_seconds)
                with RouterOsClient(client_login, self.app_config.connect_timeout_seconds, self.app_config.command_timeout_seconds) as client:
                    check = check_wireguard_reachability(client, link)
                    if check.reachable:
                        state.last_repair_ts = now
                        state.consecutive_failures = 0
                        self.logger.info("repair success for %s", link.name)
                        return True
            except Exception as exc:
                self.logger.exception("repair attempt failed for %s: %s", link.name, exc)
            self.logger.warning("repair retry %s/%s for %s", attempt + 1, link.repair_max_retries, link.name)

        state.last_repair_ts = now
        state.consecutive_failures += 1
        if state.consecutive_failures >= 3:
            state.circuit_open_until = now + link.repair_cooldown_seconds
        return False

    def _repair_once(self, link: RouterLinkConfig, client_login: LoginInfo, server_login: LoginInfo) -> None:
        new_server_port = random.randint(12000, 64000)
        new_client_port = new_server_port - 1

        with RouterOsClient(client_login, self.app_config.connect_timeout_seconds, self.app_config.command_timeout_seconds) as client:
            client_wg_id, client_peer_id = self._resolve_ids(
                client,
                wireguard_name=link.wireguard.client_wireguard_name,
                wireguard_id=link.wireguard.client_wireguard_id,
                peer_id=link.wireguard.client_peers_id,
            )
            client.talk(
                [
                    "/interface/wireguard/set",
                    f"=listen-port={new_client_port}",
                    f"=.id={client_wg_id}",
                ]
            )
            client.talk(
                [
                    "/interface/wireguard/peers/set",
                    f"=endpoint-port={new_server_port}",
                    f"=.id={client_peer_id}",
                ]
            )

        with RouterOsClient(server_login, self.app_config.connect_timeout_seconds, self.app_config.command_timeout_seconds) as server:
            server_wg_id, server_peer_id = self._resolve_ids(
                server,
                wireguard_name=link.wireguard.server_wireguard_name,
                wireguard_id=link.wireguard.server_wireguard_id,
                peer_id=link.wireguard.server_peers_id,
            )
            server.talk(
                [
                    "/interface/wireguard/set",
                    f"=listen-port={new_server_port}",
                    f"=.id={server_wg_id}",
                ]
            )
            server.talk(
                [
                    "/interface/wireguard/peers/set",
                    f"=endpoint-port={new_client_port}",
                    f"=.id={server_peer_id}",
                ]
            )
            server.talk(["/interface/wireguard/set", "=disabled=no", f"=.id={server_wg_id}"])
            server.talk(["/interface/wireguard/peers/set", "=disabled=no", f"=.id={server_peer_id}"])

    def _resolve_ids(
        self,
        client: RouterOsClient,
        wireguard_name: str,
        wireguard_id: str | None,
        peer_id: str | None,
    ) -> tuple[str, str]:
        resolved_wg_id = wireguard_id or ""
        if not resolved_wg_id:
            rows = client.talk(["/interface/wireguard/print", f"?name={wireguard_name}"])
            for _, attrs in rows:
                resolved_wg_id = attrs.get("=.id", "")
                if resolved_wg_id:
                    break
        if not resolved_wg_id:
            raise RuntimeError(f"wireguard interface not found by name: {wireguard_name}")

        resolved_peer_id = peer_id or ""
        if not resolved_peer_id:
            rows = client.talk(["/interface/wireguard/peers/print", f"?interface={wireguard_name}"])
            for _, attrs in rows:
                resolved_peer_id = attrs.get("=.id", "")
                if resolved_peer_id:
                    break
        if not resolved_peer_id:
            raise RuntimeError(f"wireguard peer not found for interface: {wireguard_name}")
        return resolved_wg_id, resolved_peer_id
