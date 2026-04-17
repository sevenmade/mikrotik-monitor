# Runbook

## 启动

```bash
python3 -m src.app --config ./config/routers.yaml --web-port 5001
```

## 常见问题

- `links section is empty`：已支持空 links，请确认代码为最新版本。
- `client_endpoint_ref does not exist`：检查 links 里的 endpoint 名称是否和 endpoints 键一致。
- 速率显示 0：为 endpoint 配置 `wan_interface`（如 `ether1`）。

## 告警

- 设置环境变量 `MT_ALERT_WEBHOOK_URL`
- 触发条件：
  - 健康检查异常
  - 自动修复失败
