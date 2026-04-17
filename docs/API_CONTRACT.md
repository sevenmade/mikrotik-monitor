# API Contract

## `GET /api/routers-status`

返回设备维度数据（用于设备卡片）：

- `name`: 设备名称
- `host`: 设备地址
- `port`: 端口
- `tx_bps`: WAN 上传速率（bps）
- `rx_bps`: WAN 下载速率（bps）
- `wan_interface`: 使用的 WAN 接口名
- `updated_at_iso`: 更新时间

## `GET /api/status`

返回链路维度数据（用于链路表格）：

- `name`
- `client_endpoint`
- `server_endpoint`
- `health_ok`
- `packet_loss`
- `reason`
- `repair_attempted`
- `repair_success`
- `consecutive_failures`
- `circuit_open`
- `last_check_iso`

## `GET /api/config/endpoints`

返回设备配置：

- `name`
- `host`
- `port`
- `username`
- `password`
- `wan_interface`

## `GET /api/config/links`

返回链路配置：

- `name`
- `server_endpoint_ref`
- `client_endpoint_ref`
- `server_wireguard_name`
- `client_wireguard_name`
- `wg_subnet`
- `server_ping_ip`
