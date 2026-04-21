from __future__ import annotations

import json
import logging
import traceback
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
        try:
            item = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "source": f"{record.filename}:{record.lineno}",
                "thread": record.threadName,
            }
            if record.exc_info:
                item["exception"] = "".join(traceback.format_exception(*record.exc_info))
            with _log_buffer_lock:
                _log_buffer.append(item)
        except Exception:
            # Never let auxiliary log buffering break primary logging output.
            return


def get_recent_logs(limit: int = 200, level: str = "ALL") -> list[dict[str, str]]:
    safe_limit = max(1, min(int(limit), _LOG_BUFFER_MAX))
    level_upper = str(level or "ALL").upper()
    allowed = {"DEBUG", "INFO", "WARNING", "ERROR"}
    with _log_buffer_lock:
        rows = list(_log_buffer)
    if level_upper in allowed:
        rows = [row for row in rows if str(row.get("level", "")).upper() == level_upper]
    rows = rows[-safe_limit:]
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
