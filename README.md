# Mikrotik Monitor

多路由器并发监控与 WireGuard 自动保活服务（线程池 + 单容器）。

## 快速开始

1. 复制配置模板：
   - `cp config/routers.example.yaml config/routers.yaml`
   - `cp .env.example .env`
2. 编辑 `config/routers.yaml`：
   - 配置 `endpoints`、`links`
   - 每个 `endpoint` 自己填写 `username` 与 `password`
   - 可选填写 `wan_interface` 指定 WAN 口名称（如 `ether1`）
   - `links` 可为空（仅查看设备WAN速率）
3. `.env` 仅用于服务启动参数（如端口、配置路径）。

## 本地运行

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m src.app --config ./config/routers.yaml
```

## Docker 运行

```bash
docker compose up -d --build
docker compose logs -f
```

启动后访问：

- `http://<你的主机IP>:5001/`：Web 状态面板
- `http://<你的主机IP>:5001/api/status`：状态 JSON 接口
- `http://<你的主机IP>:5001/api/routers-status`：设备 WAN 速率接口

## 运行逻辑

- 每个巡检周期并发执行所有 `links`。
- 每个巡检周期并发采集所有 `endpoints` 的 WAN 上下行速率。
- 对每个 link 先健康检查（ping 对端 wg server_ip）。
- 失败时执行修复：重新分配端口 + 启用接口/peer + 延迟复检。
- 修复有冷却时间、有限重试和简易熔断保护。
- 同时提供 Web 面板查看设备WAN速率、链路状态、修复结果、连续失败次数。

## 告警（可选）

- 配置 `MT_ALERT_WEBHOOK_URL` 后，链路检测失败和修复失败会推送 webhook。
