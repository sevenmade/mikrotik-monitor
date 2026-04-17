"""Development auto-restart: parent watches source/config mtimes and respawns the real worker."""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def _watch_snap(project_root: Path, config_path: str) -> dict[str, float]:
    snap: dict[str, float] = {}
    src = project_root / "src"
    if src.is_dir():
        for p in src.rglob("*.py"):
            if p.is_file():
                try:
                    snap[str(p.resolve())] = p.stat().st_mtime
                except OSError:
                    continue
    cfg = Path(config_path).expanduser()
    if cfg.is_file():
        try:
            snap[str(cfg.resolve())] = cfg.stat().st_mtime
        except OSError:
            pass
    return snap


def run_dev_reloader(*, project_root: Path, config_path: str) -> int:
    """Run ``python -m src.app …`` in a subprocess; restart when watched files change."""
    if os.environ.get("MT_MONITOR_CHILD") == "1":
        raise RuntimeError("dev reloader must not nest (MT_MONITOR_CHILD already set)")

    child_env = os.environ.copy()
    child_env["MT_MONITOR_CHILD"] = "1"
    argv = [sys.executable, "-m", "src.app", *sys.argv[1:]]
    cwd = str(project_root.resolve())
    proc_holder: list[subprocess.Popen | None] = [None]

    def _stop_parent(*_args: object) -> None:
        proc = proc_holder[0]
        if proc is not None and proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _stop_parent)
    signal.signal(signal.SIGTERM, _stop_parent)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", force=True)
    logger.info("debug 模式：监控源码与配置变更，将自动重启子进程（工作目录 %s）", cwd)

    while True:
        logger.info("启动子进程…")
        proc = subprocess.Popen(argv, env=child_env, cwd=cwd)
        proc_holder[0] = proc
        snap = _watch_snap(project_root, config_path)
        restart = False
        try:
            while proc.poll() is None:
                time.sleep(0.6)
                now = _watch_snap(project_root, config_path)
                if now != snap:
                    snap = now
                    restart = True
                    logger.info("检测到文件变更，正在重启…")
                    proc.send_signal(signal.SIGTERM)
                    try:
                        proc.wait(timeout=25)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                    break
        finally:
            proc_holder[0] = None

        if not restart:
            code = proc.returncode
            return 0 if code is None else int(code)
