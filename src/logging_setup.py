from __future__ import annotations

import json
import logging
from collections import deque
from datetime import datetime, timezone
from threading import Lock

_LOG_BUFFER_MAX = 600
_log_buffer: deque[dict[str, str]] = deque(maxlen=_LOG_BUFFER_MAX)
_log_buffer_lock = Lock()


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


class InMemoryBufferHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        item = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            item["exception"] = self.formatException(record.exc_info)
        with _log_buffer_lock:
            _log_buffer.append(item)


def get_recent_logs(limit: int = 200) -> list[dict[str, str]]:
    safe_limit = max(1, min(int(limit), _LOG_BUFFER_MAX))
    with _log_buffer_lock:
        rows = list(_log_buffer)[-safe_limit:]
    rows.reverse()
    return rows


def setup_logging(level: str) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level.upper())
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.addHandler(InMemoryBufferHandler())
