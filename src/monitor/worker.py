from __future__ import annotations

import logging
import time
from threading import Lock

from src.alerts.notifier import AlertEvent, Notifier
from src.config.loader import resolve_password
from src.config.models import AppConfig, RouterLinkConfig
from src.monitor.checks import check_wireguard_reachability, sample_wan_rate_bps, sample_wireguard_rate_bps
from src.monitor.healer import RepairState, WireGuardHealer
from src.monitor.status_store import StatusStore
from src.routeros.client import LoginInfo, RouterOsClient


class RouterWorker:
    def __init__(self, app_config: AppConfig, status_store: StatusStore, notifier: Notifier | None = None):
        self.app_config = app_config
        self.logger = logging.getLogger(__name__)
        self.healer = WireGuardHealer(app_config)
        self.status_store = status_store
        self.notifier = notifier or Notifier()
        self._states: dict[str, RepairState] = {}
        self._locks: dict[str, Lock] = {}
        self._config_lock = Lock()

    def set_app_config(self, app_config: AppConfig) -> None:
        with self._config_lock:
            self.app_config = app_config

    def get_app_config(self) -> AppConfig:
        with self._config_lock:
            return self.app_config

    def run_link(self, link: RouterLinkConfig) -> None:
        lock = self._locks.setdefault(link.name, Lock())
        if not lock.acquire(blocking=False):
            self.logger.info("repair in progress, skip duplicate task: %s", link.name)
            return
        try:
            self._run_link_locked(link)
        finally:
            lock.release()

    def run_endpoint(self, endpoint_name: str) -> None:
        with self._config_lock:
            current_config = self.app_config
        endpoint = current_config.endpoints.get(endpoint_name)
        if endpoint is None:
            return
        try:
            login = LoginInfo(
                host=endpoint.host,
                port=endpoint.port,
                username=endpoint.username,
                password=resolve_password(endpoint.password),
            )
            with RouterOsClient(
                login,
                connect_timeout=current_config.connect_timeout_seconds,
                command_timeout=current_config.command_timeout_seconds,
            ) as client:
                tx_bps, rx_bps, iface_name = sample_wan_rate_bps(client, endpoint.wan_interface)
            self.status_store.upsert_router(
                endpoint.name,
                {
                    "host": endpoint.host,
                    "port": endpoint.port,
                    "tx_bps": tx_bps,
                    "rx_bps": rx_bps,
                    "wan_interface": iface_name,
                    "display_index": endpoint.display_index,
                },
            )
        except Exception as exc:
            self.logger.debug("endpoint sample failed for %s: %s", endpoint.name, exc)
            self.status_store.upsert_router(
                endpoint.name,
                {
                    "host": endpoint.host,
                    "port": endpoint.port,
                    "tx_bps": 0.0,
                    "rx_bps": 0.0,
                    "wan_interface": endpoint.wan_interface or "",
                    "display_index": endpoint.display_index,
                },
            )

    def _run_link_locked(self, link: RouterLinkConfig) -> None:
        state = self._states.setdefault(link.name, RepairState())
        check_ts = time.time()
        client_login, server_login = self._build_login_info(link)

        try:
            with RouterOsClient(
                client_login,
                connect_timeout=self.app_config.connect_timeout_seconds,
                command_timeout=self.app_config.command_timeout_seconds,
            ) as client:
                health = check_wireguard_reachability(client, link)
                tx_bps, rx_bps = sample_wireguard_rate_bps(client, link)
        except Exception as exc:
            self.logger.exception("health check failed for %s: %s", link.name, exc)
            state.consecutive_failures += 1
            self._update_status_base(link, state, check_ts)
            self.status_store.upsert(link.name, lambda s: self._apply_failed_check(s, str(exc)))
            self._notify("warning", f"{link.name} 健康检查失败", str(exc))
            return

        self._update_status_base(link, state, check_ts)
        self.status_store.upsert(link.name, lambda s: s.set_rates(tx_bps=tx_bps, rx_bps=rx_bps))
        if health.reachable:
            self.logger.info("wireguard ok: %s packet-loss=%s", link.name, health.packet_loss)
            state.consecutive_failures = 0
            self.status_store.upsert(
                link.name,
                lambda s: self._apply_health_result(
                    s=s,
                    ok=True,
                    packet_loss=health.packet_loss,
                    reason=health.reason,
                    repair_attempted=False,
                    repair_success=False,
                    state=state,
                ),
            )
            return

        self.logger.warning("wireguard failed: %s reason=%s", link.name, health.reason)
        repair_success = self.healer.attempt_repair(link=link, state=state, client_login=client_login, server_login=server_login)
        if not repair_success:
            self._notify("error", f"{link.name} 自动修复失败", health.reason)
        self.status_store.upsert(
            link.name,
            lambda s: self._apply_health_result(
                s=s,
                ok=False,
                packet_loss=health.packet_loss,
                reason=health.reason,
                repair_attempted=True,
                repair_success=repair_success,
                state=state,
            ),
        )

    def _build_login_info(self, link: RouterLinkConfig) -> tuple[LoginInfo, LoginInfo]:
        with self._config_lock:
            current_config = self.app_config
        client_endpoint = current_config.endpoints[link.client_endpoint_ref]
        server_endpoint = current_config.endpoints[link.server_endpoint_ref]

        client_login = LoginInfo(
            host=client_endpoint.host,
            port=client_endpoint.port,
            username=client_endpoint.username,
            password=resolve_password(client_endpoint.password),
        )
        server_login = LoginInfo(
            host=server_endpoint.host,
            port=server_endpoint.port,
            username=server_endpoint.username,
            password=resolve_password(server_endpoint.password),
        )
        return client_login, server_login

    def _update_status_base(self, link: RouterLinkConfig, state: RepairState, check_ts: float) -> None:
        with self._config_lock:
            current_config = self.app_config
        client_endpoint = current_config.endpoints[link.client_endpoint_ref]
        server_endpoint = current_config.endpoints[link.server_endpoint_ref]

        def _apply(entry):
            entry.client_endpoint = f"{client_endpoint.host}:{client_endpoint.port}"
            entry.server_endpoint = f"{server_endpoint.host}:{server_endpoint.port}"
            entry.last_check_ts = check_ts
            entry.consecutive_failures = state.consecutive_failures
            entry.circuit_open = time.time() < state.circuit_open_until

        self.status_store.upsert(link.name, _apply)

    @staticmethod
    def _apply_failed_check(s, reason: str) -> None:
        s.health_ok = False
        s.packet_loss = None
        s.reason = f"health check exception: {reason}"
        s.repair_attempted = False
        s.repair_success = False

    @staticmethod
    def _apply_health_result(s, ok: bool, packet_loss, reason: str, repair_attempted: bool, repair_success: bool, state: RepairState) -> None:
        s.health_ok = ok
        s.packet_loss = packet_loss
        s.reason = reason
        s.repair_attempted = repair_attempted
        s.repair_success = repair_success
        s.consecutive_failures = state.consecutive_failures

    def _notify(self, level: str, title: str, message: str) -> None:
        try:
            self.notifier.notify(AlertEvent(level=level, title=title, message=message))
        except Exception as exc:
            self.logger.debug("notify failed: %s", exc)
