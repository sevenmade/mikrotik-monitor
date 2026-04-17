#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


def _get_json(url: str, timeout: float) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    return json.loads(body)


def _expect_envelope(name: str, payload: dict, *, data_type: type | None = None) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, f"{name}: 响应不是 JSON 对象"
    if payload.get("ok") is not True:
        return False, f"{name}: ok 字段不是 true"
    if "data" not in payload:
        return False, f"{name}: 缺少 data 字段"
    if data_type is not None and not isinstance(payload.get("data"), data_type):
        return False, f"{name}: data 字段类型错误，期望 {data_type.__name__}"
    return True, f"{name}: PASS"


def main() -> int:
    parser = argparse.ArgumentParser(description="Mikrotik App API self-check")
    parser.add_argument("--base-url", default="http://127.0.0.1:5001", help="API base url")
    parser.add_argument("--timeout", type=float, default=3.0, help="HTTP timeout seconds")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    checks = [
        ("healthz", f"{base}/healthz", None),
        ("status", f"{base}/api/status", list),
        ("routers-status", f"{base}/api/routers-status", list),
        ("config/endpoints", f"{base}/api/config/endpoints", list),
        ("config/links", f"{base}/api/config/links", list),
    ]

    failed = 0
    for name, url, data_type in checks:
        try:
            payload = _get_json(url, timeout=args.timeout)
            if name == "healthz":
                ok = isinstance(payload, dict) and payload.get("ok") is True
                if ok:
                    print(f"{name}: PASS")
                else:
                    print(f"{name}: FAIL - 响应缺少 ok=true")
                    failed += 1
                continue
            ok, msg = _expect_envelope(name, payload, data_type=data_type)
            print(msg)
            if not ok:
                failed += 1
        except urllib.error.HTTPError as exc:
            print(f"{name}: FAIL - HTTP {exc.code}")
            failed += 1
        except urllib.error.URLError as exc:
            print(f"{name}: FAIL - 网络错误: {exc.reason}")
            failed += 1
        except json.JSONDecodeError:
            print(f"{name}: FAIL - 响应不是有效 JSON")
            failed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"{name}: FAIL - {exc}")
            failed += 1

    if failed:
        print(f"\nSelf-check 未通过: {failed} 项失败")
        return 1
    print("\nSelf-check 通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
