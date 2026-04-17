from __future__ import annotations

import argparse
import logging
import os
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path

from src.alerts.notifier import Notifier
from src.config.loader import ConfigError, load_app_config
from src.config.runtime_config import RuntimeConfigStore
from src.dev_reloader import run_dev_reloader
from src.logging_setup import setup_logging
from src.monitor.status_store import StatusStore
from src.monitor.worker import RouterWorker
from src.web.server import start_web_server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mikrotik monitor and WireGuard keeper")
    parser.add_argument(
        "--config",
        default=os.getenv("MT_CONFIG_PATH", "/app/config/routers.yaml"),
        help="Path to routers yaml config",
    )
    parser.add_argument("--web-host", default=os.getenv("MT_WEB_HOST", "0.0.0.0"), help="Web UI bind host")
    parser.add_argument("--web-port", type=int, default=int(os.getenv("MT_WEB_PORT", "5001")), help="Web UI port")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="开发模式：日志级别 DEBUG，并在修改 src 下 .py 或配置文件时自动重启进程",
    )
    return parser.parse_args()


def write_heartbeat(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(str(int(time.time())), encoding="utf-8")


def _run_monitor(args: argparse.Namespace) -> int:
    try:
        app_config = load_app_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}")
        return 2

    log_level = "DEBUG" if args.debug else app_config.log_level
    setup_logging(log_level)
    logger = logging.getLogger(__name__)
    config_store = RuntimeConfigStore(args.config)
    web_password, generated = config_store.ensure_web_password()
    if generated:
        logger.warning("首次部署已生成登录密码，请尽快修改 settings.web_password: %s", web_password)
    status_store = StatusStore()
    worker = RouterWorker(app_config, status_store, notifier=Notifier())
    stop_event = threading.Event()
    def _reload_runtime_config() -> None:
        refreshed = load_app_config(args.config)
        worker.set_app_config(refreshed)

    web_server = start_web_server(
        status_store=status_store,
        config_store=config_store,
        reload_config_callback=_reload_runtime_config,
        host=args.web_host,
        port=args.web_port,
    )

    def _stop(*_):
        logger.info("stop signal received")
        stop_event.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    logger.info(
        "service started, links=%s workers=%s web=http://%s:%s",
        len(app_config.links),
        app_config.max_workers,
        args.web_host,
        args.web_port,
    )
    with ThreadPoolExecutor(max_workers=app_config.max_workers, thread_name_prefix="router-worker") as pool:
        while not stop_event.is_set():
            active_config = worker.get_app_config()
            write_heartbeat(active_config.heartbeat_file)
            endpoint_names = list(active_config.endpoints.keys())
            futures = [pool.submit(worker.run_endpoint, endpoint_name) for endpoint_name in endpoint_names]
            futures.extend(pool.submit(worker.run_link, link) for link in active_config.links)
            wait(futures)
            stop_event.wait(active_config.poll_interval_seconds)

    web_server.shutdown()
    web_server.server_close()
    logger.info("service stopped")
    return 0


def main() -> int:
    args = parse_args()
    project_root = Path(__file__).resolve().parent.parent
    if args.debug and os.environ.get("MT_MONITOR_CHILD") != "1":
        return run_dev_reloader(project_root=project_root, config_path=args.config)
    return _run_monitor(args)


if __name__ == "__main__":
    raise SystemExit(main())
