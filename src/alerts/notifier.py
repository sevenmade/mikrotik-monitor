from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class AlertEvent:
    level: str
    title: str
    message: str


class Notifier:
    def __init__(self) -> None:
        self.webhook_url = os.getenv("MT_ALERT_WEBHOOK_URL", "").strip()

    def notify(self, event: AlertEvent) -> None:
        if not self.webhook_url:
            return
        payload = {
            "level": event.level,
            "title": event.title,
            "message": event.message,
        }
        request = urllib.request.Request(
            self.webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(request, timeout=5).read()
