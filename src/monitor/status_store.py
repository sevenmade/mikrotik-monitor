from __future__ import annotations

import threading
import time
from dataclasses import dataclass, asdict
from typing import Any


def _push_limit(items: list[float], value: float, limit: int = 30) -> list[float]:
    items.append(value)
    if len(items) > limit:
        return items[-limit:]
    return items


@dataclass
class LinkStatus:
    name: str
    client_endpoint: str
    server_endpoint: str
    last_check_ts: float = 0.0
    health_ok: bool = False
    packet_loss: int | None = None
    reason: str = "never checked"
    repair_attempted: bool = False
    repair_success: bool = False
    consecutive_failures: int = 0
    circuit_open: bool = False
    tx_bps: float = 0.0
    rx_bps: float = 0.0
    tx_history: list[float] | None = None
    rx_history: list[float] | None = None
    updated_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        if self.tx_history is None:
            self.tx_history = []
        if self.rx_history is None:
            self.rx_history = []
        payload = asdict(self)
        payload["last_check_iso"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_check_ts)) if self.last_check_ts else "-"
        payload["updated_at_iso"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.updated_at)) if self.updated_at else "-"
        return payload

    def set_rates(self, tx_bps: float, rx_bps: float) -> None:
        if self.tx_history is None:
            self.tx_history = []
        if self.rx_history is None:
            self.rx_history = []
        self.tx_bps = max(0.0, tx_bps)
        self.rx_bps = max(0.0, rx_bps)
        self.tx_history = _push_limit(self.tx_history, self.tx_bps)
        self.rx_history = _push_limit(self.rx_history, self.rx_bps)


class StatusStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._status: dict[str, LinkStatus] = {}
        self._router_status: dict[str, dict[str, Any]] = {}

    def upsert(self, link_name: str, updater) -> None:
        with self._lock:
            entry = self._status.get(link_name)
            if entry is None:
                entry = LinkStatus(name=link_name, client_endpoint="", server_endpoint="")
                self._status[link_name] = entry
            updater(entry)
            entry.updated_at = time.time()

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            data = [item.to_dict() for item in self._status.values()]
        data.sort(key=lambda x: x["name"])
        return data

    def upsert_router(self, router_name: str, payload: dict[str, Any]) -> None:
        with self._lock:
            current = self._router_status.get(router_name, {})
            current.update(payload)
            tx_bps = float(current.get("tx_bps", 0) or 0)
            rx_bps = float(current.get("rx_bps", 0) or 0)
            tx_history = current.get("tx_history")
            rx_history = current.get("rx_history")
            if not isinstance(tx_history, list):
                tx_history = []
            if not isinstance(rx_history, list):
                rx_history = []
            current["tx_history"] = _push_limit(tx_history, max(0.0, tx_bps))
            current["rx_history"] = _push_limit(rx_history, max(0.0, rx_bps))
            current["name"] = router_name
            current["updated_at"] = time.time()
            self._router_status[router_name] = current

    def snapshot_routers(self) -> list[dict[str, Any]]:
        with self._lock:
            data = []
            for row in self._router_status.values():
                item = dict(row)
                updated_at = float(item.get("updated_at", 0) or 0)
                item["updated_at_iso"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(updated_at)) if updated_at else "-"
                data.append(item)
        data.sort(key=lambda x: (int(x.get("display_index", 0) or 0), str(x.get("name", ""))))
        return data
