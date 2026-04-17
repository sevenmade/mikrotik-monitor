from __future__ import annotations

import ipaddress
import json
import secrets
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse

from src.config.runtime_config import RuntimeConfigStore
from src.monitor.status_store import StatusStore
from src.routeros.client import RouterOsError
from src.routeros.wireguard_discovery import list_wireguard_interface_names


def _serialize_routers_status(store: StatusStore, config_store: RuntimeConfigStore) -> str:
    rows = store.snapshot_routers()
    try:
        endpoints = config_store.list_endpoints()
    except Exception:
        endpoints = []
    order = {e["name"]: int(e.get("display_index", 0) or 0) for e in endpoints}
    for row in rows:
        name = str(row.get("name", ""))
        row["display_index"] = order.get(name, int(row.get("display_index", 0) or 0))
    rows.sort(key=lambda r: (int(r.get("display_index", 0) or 0), str(r.get("name", ""))))
    return json.dumps(rows, ensure_ascii=False)


def _require_non_empty(payload: dict, key: str, label: str) -> str:
    value = str(payload.get(key, "")).strip()
    if not value:
        raise ValueError(f"{label}不能为空")
    return value


def _parse_int_in_range(payload: dict, key: str, label: str, min_value: int, max_value: int) -> int:
    raw = payload.get(key, "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{label}必须是整数")
    if value < min_value or value > max_value:
        raise ValueError(f"{label}必须在 {min_value} 到 {max_value} 之间")
    return value


def _validate_endpoint_payload(payload: dict) -> None:
    _require_non_empty(payload, "name", "路由器名称")
    _require_non_empty(payload, "host", "Host/域名")
    _require_non_empty(payload, "username", "用户名")
    _require_non_empty(payload, "password", "密码")
    _parse_int_in_range(payload, "port", "端口", 1, 65535)
    if "display_index" in payload:
        _parse_int_in_range(payload, "display_index", "显示顺序", -999999, 999999)


def _validate_link_payload(payload: dict) -> None:
    _require_non_empty(payload, "name", "连接名称")
    _require_non_empty(payload, "server_endpoint_ref", "服务器路由器设备")
    _require_non_empty(payload, "client_endpoint_ref", "客户端路由器设备")
    _require_non_empty(payload, "server_wireguard_name", "服务器 WG 连接名称")
    _require_non_empty(payload, "client_wireguard_name", "客户端 WG 连接名称")
    subnet = _require_non_empty(payload, "wg_subnet", "WG 网段")
    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise ValueError("WG 网段格式不正确，例如 10.10.0.0/24") from exc


def _validate_settings_payload(payload: dict) -> None:
    def _int_range(key: str, label: str, min_v: int, max_v: int) -> None:
        if key not in payload:
            return
        try:
            value = int(payload.get(key))
        except (TypeError, ValueError):
            raise ValueError(f"{label}必须是整数")
        if value < min_v or value > max_v:
            raise ValueError(f"{label}必须在 {min_v} 到 {max_v} 之间")

    _int_range("poll_interval_seconds", "轮询间隔", 5, 3600)
    _int_range("max_workers", "最大并发", 1, 256)
    _int_range("connect_timeout_seconds", "连接超时", 1, 120)
    _int_range("command_timeout_seconds", "命令超时", 1, 300)
    _int_range("recheck_delay_seconds", "复检延迟", 1, 300)
    if "heartbeat_file" in payload and not str(payload.get("heartbeat_file", "")).strip():
        raise ValueError("心跳文件路径不能为空")
    if "log_level" in payload:
        level = str(payload.get("log_level", "")).strip().upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
            raise ValueError("日志级别仅支持 DEBUG/INFO/WARNING/ERROR")
    if "web_password" in payload:
        pwd = str(payload.get("web_password", "")).strip()
        if len(pwd) < 8:
            raise ValueError("访问密码至少 8 位")


def _html_page() -> str:
    return """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mikrotik Monitor Dashboard</title>
  <style>
    :root{
      --bg:#0b1220;
      --panel:#111a2e;
      --panel-soft:#17233d;
      --text:#e6ecff;
      --muted:#98a4c7;
      --ok:#28c76f;
      --bad:#ff5b5b;
      --warn:#ffb74d;
      --line:#243458;
      --chip:#213056;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      background: radial-gradient(1200px 800px at 10% -20%, #22345f 0%, var(--bg) 45%);
      color: var(--text);
    }
    .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 16px; }
    .title { font-size: 24px; font-weight: 700; margin: 0; }
    .title-row { display: flex; align-items: center; gap: 8px; }
    .version-tag {
      font-size: 12px;
      color: var(--muted);
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 2px 8px;
      background: var(--chip);
    }
    .subtitle { color: var(--muted); font-size: 14px; margin-top: 6px; }
    .refresh-tag {
      background: var(--chip);
      color: var(--muted);
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 8px 12px;
      font-size: 12px;
      white-space: nowrap;
    }
    .cards {
      display: grid;
      grid-template-columns: repeat(4, minmax(160px, 1fr));
      gap: 12px;
      margin-bottom: 14px;
    }
    .device-cards {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 14px;
    }
    .device-card {
      background: linear-gradient(180deg, #162648 0%, var(--panel) 100%);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 12px;
    }
    .device-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
      margin-bottom: 8px;
    }
    .icon-btn {
      border: 1px solid var(--line);
      background: #0f1830;
      color: var(--muted);
      border-radius: 8px;
      width: 28px;
      height: 28px;
      line-height: 26px;
      text-align: center;
      cursor: pointer;
      font-size: 14px;
      padding: 0;
    }
    .icon-btn:hover { color: var(--text); border-color: #3a4f80; }
    .device-name { font-weight: 700; font-size: 15px; }
    .host-line { color: var(--muted); font-size: 12px; margin-bottom: 10px; word-break: break-all; }
    .speed-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
    .speed-box {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #0f1830;
      padding: 8px;
    }
    .speed-label { color: var(--muted); font-size: 11px; margin-bottom: 4px; }
    .speed-value { font-size: 16px; font-weight: 700; }
    .device-card .speed-value { font-size: 13px; font-weight: 600; }
    .mini-chart {
      width: 100%;
      height: 78px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #0f1830;
      display: block;
      margin-top: 10px;
    }
    .chart-legend { color: var(--muted); font-size: 11px; margin-top: 6px; }
    .card {
      background: linear-gradient(180deg, #162648 0%, var(--panel) 100%);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px;
    }
    .card .label { color: var(--muted); font-size: 12px; margin-bottom: 8px; }
    .card .value { font-size: 28px; font-weight: 700; line-height: 1; }
    .ok-text { color: var(--ok); }
    .bad-text { color: var(--bad); }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      overflow: hidden;
    }
    .toolbar { display: flex; justify-content: flex-end; padding: 10px; border-bottom: 1px solid var(--line); }
    .btn {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 8px 10px;
      background: var(--chip);
      color: var(--text);
      cursor: pointer;
      font-size: 12px;
    }
    .btn:hover { opacity: 0.9; }
    .btn-danger { background: #51202a; border-color: #7a3342; }
    .btn-inline { padding: 4px 8px; font-size: 12px; }
    .table-wrap { overflow: auto; }
    .endpoint-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      padding: 12px;
    }
    .endpoint-item {
      border: 1px solid var(--line);
      background: #0f1830;
      border-radius: 10px;
      padding: 10px;
    }
    .endpoint-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
      gap: 10px;
    }
    .kv { color: var(--muted); font-size: 12px; margin-bottom: 4px; }
    .modal-mask {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.5);
      align-items: center;
      justify-content: center;
      z-index: 20;
    }
    .modal {
      width: min(680px, 94vw);
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px;
    }
    .form-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin-top: 10px;
    }
    .form-grid .full { grid-column: 1 / -1; }
    .field label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 4px; }
    .field-hint { display: block; font-size: 11px; color: var(--muted); opacity: 0.9; margin-bottom: 4px; }
    .field input, .field select {
      width: 100%;
      border: 1px solid var(--line);
      background: #0f1830;
      color: var(--text);
      border-radius: 8px;
      padding: 8px;
      font-size: 13px;
    }
    .modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 12px; }
    table { border-collapse: collapse; width: 100%; min-width: 920px; }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 12px 10px;
      font-size: 13px;
      text-align: left;
      vertical-align: top;
    }
    .ta-center { text-align: center; }
    .ta-right { text-align: right; }
    .footer-links a { color: #b7c5ea; text-decoration: none; }
    .footer-links a:hover { text-decoration: underline; }
    th {
      background: var(--panel-soft);
      color: #b7c5ea;
      position: sticky;
      top: 0;
      z-index: 1;
    }
    tr:hover td { background: rgba(255,255,255,0.02); }
    .muted { color: var(--muted); }
    .chip {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      border: 1px solid var(--line);
      background: var(--chip);
    }
    .chip-ok { color: #0f301f; background: var(--ok); border-color: transparent; }
    .chip-bad { color: #350d12; background: var(--bad); border-color: transparent; }
    .chip-warn { color: #3b2506; background: var(--warn); border-color: transparent; }
    .reason { max-width: 320px; word-break: break-word; }
    @media (max-width: 900px){
      .cards { grid-template-columns: repeat(2, minmax(140px, 1fr)); }
      .endpoint-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .title { font-size: 20px; }
    }
    @media (max-width: 600px){
      .endpoint-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="topbar">
      <div>
        <div class="title-row">
          <h1 class="title">Mikrotik 网络状态面板</h1>
          <span class="version-tag">v1.0.1</span>
        </div>
        <div class="subtitle">实时显示设备到主设备连接情况、丢包和自动修复结果</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center;">
        <button class="btn btn-inline" title="系统设置" onclick="openSettingsModal()">⚙</button>
        <button class="btn btn-inline" onclick="logout()">退出登录</button>
      </div>
    </div>

    <div class="cards">
      <div class="card">
        <div class="label">路由器总数</div>
        <div class="value" id="totalCount">0</div>
      </div>
      <div class="card">
        <div class="label">连接正常</div>
        <div class="value ok-text" id="okCount">0</div>
      </div>
      <div class="card">
        <div class="label">连接异常</div>
        <div class="value bad-text" id="badCount">0</div>
      </div>
      <div class="card">
        <div class="label">熔断中</div>
        <div class="value" id="circuitCount">0</div>
      </div>
    </div>

    <div class="panel">
      <div class="toolbar">
        <button class="btn" onclick="openEndpointModal()">+ 新增路由器</button>
      </div>
      <div id="endpointGrid" class="endpoint-grid"></div>
    </div>
    <br>
    <div class="panel table-wrap">
      <div class="toolbar">
        <button class="btn" onclick="openLinkModal()">+ 新增连接监控</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>设备名称</th>
            <th>服务器名称</th>
            <th class="ta-center">连接状态</th>
            <th class="ta-center">丢包率</th>
            <th class="ta-right">上传速度</th>
            <th class="ta-right">下载速度</th>
            <th class="ta-center">最近检查</th>
            <th class="ta-center">操作</th>
          </tr>
        </thead>
        <tbody id="linkMonitorRows"></tbody>
      </table>
    </div>
    <div class="muted footer-links" style="text-align:center;margin-top:14px;font-size:12px;">
      Copyright © 2026 sevenmade. All rights reserved.
      &nbsp;|&nbsp;
      <a href="/LICENSE" target="_blank" rel="noopener noreferrer">授权文件</a>
      &nbsp;|&nbsp;
      <a href="https://github.com/sevenmade/mikrotik-monitor" target="_blank" rel="noopener noreferrer">GitHub</a>
    </div>
  </div>
  <div id="endpointModalMask" class="modal-mask">
    <div class="modal">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <strong id="endpointModalTitle">新增路由器</strong>
        <button class="btn btn-inline" onclick="closeEndpointModal()">关闭</button>
      </div>
      <div class="form-grid">
        <div class="field"><label>名称（唯一）</label><input id="f_name" /></div>
        <div class="field"><label>显示顺序（索引，数字越小越靠前）</label><input id="f_display_index" type="number" step="1" /></div>
        <div class="field"><label>Host / 域名</label><input id="f_host" /></div>
        <div class="field"><label>端口</label><input id="f_port" type="number" /></div>
        <div class="field"><label>用户名</label><input id="f_username" /></div>
        <div class="field"><label>密码（可直接存yaml）</label><input id="f_password" type="password" /></div>
        <div class="field"><label>WAN接口(可选, 如ether1)</label><input id="f_wan_interface" /></div>
      </div>
      <div class="modal-actions">
        <button id="endpointDeleteBtn" class="btn btn-danger" style="display:none;" onclick="deleteEndpointFromModal()">删除</button>
        <button class="btn" onclick="closeEndpointModal()">取消</button>
        <button class="btn" onclick="saveEndpoint()">保存</button>
      </div>
    </div>
  </div>
  <div id="linkModalMask" class="modal-mask">
    <div class="modal">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <strong id="linkModalTitle">新增连接监控</strong>
        <button class="btn btn-inline" onclick="closeLinkModal()">关闭</button>
      </div>
      <div class="form-grid">
        <div class="field"><label>连接名称（唯一）</label><input id="l_name" /></div>
        <div class="field"><label>WG 网段（如 10.10.0.0/24）</label><input id="l_wg_subnet" /></div>
        <div class="field"><label>服务器路由器设备</label><select id="l_server_endpoint_ref" onchange="loadServerWireguardOptions(undefined, true)"></select></div>
        <div class="field"><label>服务器 WG 连接名称</label><select id="l_server_wireguard_name"></select></div>
        <div class="field"><label>客户端路由器设备</label><select id="l_client_endpoint_ref" onchange="loadClientWireguardOptions(undefined, true)"></select></div>
        <div class="field"><label>客户端 WG 连接名称</label><select id="l_client_wireguard_name"></select></div>
      </div>
      <div class="modal-actions">
        <button class="btn" onclick="closeLinkModal()">取消</button>
        <button class="btn" onclick="saveLink()">保存</button>
      </div>
    </div>
  </div>
  <div id="settingsModalMask" class="modal-mask">
    <div class="modal" style="width:min(860px,96vw);">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <strong>系统设置</strong>
        <button class="btn btn-inline" onclick="closeSettingsModal()">关闭</button>
      </div>
      <div style="display:flex;gap:8px;margin-top:12px;">
        <button id="settingsTabBtn" class="btn btn-inline" onclick="switchSettingsTab('form')">参数设置</button>
        <button id="yamlTabBtn" class="btn btn-inline" onclick="switchSettingsTab('yaml')">YAML 编辑</button>
      </div>
      <div id="settingsFormTab" class="form-grid">
        <div class="field"><label>poll_interval_seconds</label><input id="s_poll_interval_seconds" type="number" min="5" /></div>
        <div class="field"><label>max_workers</label><input id="s_max_workers" type="number" min="1" /></div>
        <div class="field"><label>connect_timeout_seconds</label><input id="s_connect_timeout_seconds" type="number" min="1" /></div>
        <div class="field"><label>command_timeout_seconds</label><input id="s_command_timeout_seconds" type="number" min="1" /></div>
        <div class="field"><label>recheck_delay_seconds</label><input id="s_recheck_delay_seconds" type="number" min="1" /></div>
        <div class="field"><label>log_level</label><select id="s_log_level"><option>DEBUG</option><option>INFO</option><option>WARNING</option><option>ERROR</option></select></div>
        <div class="field"><label>heartbeat_file</label><input id="s_heartbeat_file" /></div>
        <div class="field"><label>web_password</label><input id="s_web_password" type="password" /></div>
      </div>
      <div id="settingsYamlTab" style="display:none;margin-top:10px;">
        <div class="field">
          <label>routers.yaml 手动编辑</label>
          <textarea id="s_yaml_text" style="width:100%;min-height:320px;border:1px solid var(--line);background:#0f1830;color:var(--text);border-radius:8px;padding:10px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;"></textarea>
        </div>
      </div>
      <div class="modal-actions">
        <button class="btn" onclick="closeSettingsModal()">取消</button>
        <button id="settingsSaveBtn" class="btn" onclick="saveSettingsForm()">保存参数</button>
        <button id="yamlSaveBtn" class="btn" style="display:none;" onclick="saveYamlText()">保存 YAML</button>
      </div>
    </div>
  </div>
  <script>
    let editingEndpointName = null;
    let editingLinkName = null;
    let endpointCache = [];
    let linkCache = [];
    let lastLinkStatusRows = [];
    function escapeHtml(s){
      return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
    function apiData(payload){
      if(payload && typeof payload === 'object' && Object.prototype.hasOwnProperty.call(payload, 'ok')){
        return payload.data;
      }
      return payload;
    }
    function apiErrorText(payload, fallback){
      if(payload && typeof payload === 'object'){
        if(payload.error) return String(payload.error);
        if(payload.message) return String(payload.message);
      }
      return fallback;
    }
    async function openSettingsModal(){
      await loadSettingsForm();
      switchSettingsTab('form');
      document.getElementById('settingsModalMask').style.display = 'flex';
    }
    function closeSettingsModal(){
      document.getElementById('settingsModalMask').style.display = 'none';
    }
    function switchSettingsTab(tab){
      const formTab = document.getElementById('settingsFormTab');
      const yamlTab = document.getElementById('settingsYamlTab');
      const formBtn = document.getElementById('settingsTabBtn');
      const yamlBtn = document.getElementById('yamlTabBtn');
      const settingsSaveBtn = document.getElementById('settingsSaveBtn');
      const yamlSaveBtn = document.getElementById('yamlSaveBtn');
      const isYaml = tab === 'yaml';
      formTab.style.display = isYaml ? 'none' : 'grid';
      yamlTab.style.display = isYaml ? 'block' : 'none';
      settingsSaveBtn.style.display = isYaml ? 'none' : 'inline-block';
      yamlSaveBtn.style.display = isYaml ? 'inline-block' : 'none';
      formBtn.style.opacity = isYaml ? '0.7' : '1';
      yamlBtn.style.opacity = isYaml ? '1' : '0.7';
      if(isYaml){
        loadYamlText();
      }
    }
    async function loadSettingsForm(){
      const res = await fetch('/api/config/settings');
      const raw = await res.json().catch(() => ({}));
      if(!res.ok){
        alert('读取设置失败: ' + apiErrorText(raw, '未知错误'));
        return;
      }
      const s = apiData(raw) || {};
      document.getElementById('s_poll_interval_seconds').value = s.poll_interval_seconds ?? 30;
      document.getElementById('s_max_workers').value = s.max_workers ?? 20;
      document.getElementById('s_connect_timeout_seconds').value = s.connect_timeout_seconds ?? 8;
      document.getElementById('s_command_timeout_seconds').value = s.command_timeout_seconds ?? 10;
      document.getElementById('s_recheck_delay_seconds').value = s.recheck_delay_seconds ?? 10;
      document.getElementById('s_log_level').value = s.log_level || 'INFO';
      document.getElementById('s_heartbeat_file').value = s.heartbeat_file || '/tmp/mikrotik_monitor.heartbeat';
      document.getElementById('s_web_password').value = s.web_password || '';
    }
    async function saveSettingsForm(){
      const payload = {
        poll_interval_seconds: Number(document.getElementById('s_poll_interval_seconds').value),
        max_workers: Number(document.getElementById('s_max_workers').value),
        connect_timeout_seconds: Number(document.getElementById('s_connect_timeout_seconds').value),
        command_timeout_seconds: Number(document.getElementById('s_command_timeout_seconds').value),
        recheck_delay_seconds: Number(document.getElementById('s_recheck_delay_seconds').value),
        log_level: document.getElementById('s_log_level').value,
        heartbeat_file: document.getElementById('s_heartbeat_file').value.trim(),
        web_password: document.getElementById('s_web_password').value,
      };
      const res = await fetch('/api/config/settings', { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
      const raw = await res.json().catch(() => ({}));
      if(!res.ok){
        alert('保存设置失败: ' + apiErrorText(raw, '未知错误'));
        return;
      }
      alert('设置已保存并生效');
      closeSettingsModal();
    }
    async function loadYamlText(){
      const res = await fetch('/api/config/yaml');
      const raw = await res.json().catch(() => ({}));
      if(!res.ok){
        alert('读取 YAML 失败: ' + apiErrorText(raw, '未知错误'));
        return;
      }
      const data = apiData(raw) || {};
      document.getElementById('s_yaml_text').value = String(data.text || '');
    }
    async function saveYamlText(){
      const text = document.getElementById('s_yaml_text').value;
      const res = await fetch('/api/config/yaml', { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ text }) });
      const raw = await res.json().catch(() => ({}));
      if(!res.ok){
        alert('保存 YAML 失败: ' + apiErrorText(raw, '未知错误'));
        return;
      }
      alert('YAML 已保存并生效');
      closeSettingsModal();
      await refreshEndpoints();
      await refreshLinks();
      await refresh();
    }
    function populateWgSelect(sel, names, preferredValue){
      const pref = preferredValue !== undefined && preferredValue !== null && preferredValue !== ''
        ? String(preferredValue) : '';
      let list = (Array.isArray(names) ? names : []).map(String).filter(Boolean);
      if(pref && !list.includes(pref)) list = [pref, ...list];
      list.sort((a, b) => a.localeCompare(b, 'zh-CN'));
      sel.innerHTML = '<option value="">请选择 WireGuard 接口</option>' +
        list.map((n) => '<option value=' + JSON.stringify(n) + '>' + escapeHtml(n) + '</option>').join('');
      sel.value = pref && list.includes(pref) ? pref : '';
    }
    function wgNamesFromOtherLinks(role, endpointName){
      if(!endpointName || !Array.isArray(linkCache)) return [];
      const refKey = role === 'server' ? 'server_endpoint_ref' : 'client_endpoint_ref';
      const wgKey = role === 'server' ? 'server_wireguard_name' : 'client_wireguard_name';
      const seen = new Set();
      const out = [];
      linkCache.forEach((l) => {
        if(l[refKey] === endpointName && l[wgKey]){
          const v = String(l[wgKey]).trim();
          if(v && !seen.has(v)){
            seen.add(v);
            out.push(v);
          }
        }
      });
      return out;
    }
    function mergeWgNames(apiNames, role, endpointName){
      const fromApi = Array.isArray(apiNames) ? apiNames.map(String).filter(Boolean) : [];
      const fromCfg = wgNamesFromOtherLinks(role, endpointName);
      const merged = [];
      const seen = new Set();
      fromApi.forEach((n) => { if(!seen.has(n)){ seen.add(n); merged.push(n); } });
      fromCfg.forEach((n) => { if(!seen.has(n)){ seen.add(n); merged.push(n); } });
      merged.sort((a, b) => a.localeCompare(b, 'zh-CN'));
      return merged;
    }
    async function loadServerWireguardOptions(preserveValue, clearSelection){
      const ep = document.getElementById('l_server_endpoint_ref').value.trim();
      const sel = document.getElementById('l_server_wireguard_name');
      const keep = clearSelection ? '' : (preserveValue !== undefined ? String(preserveValue) : sel.value);
      if(!ep){
        sel.innerHTML = '<option value="">请先选择服务器路由器</option>';
        return;
      }
      sel.innerHTML = '<option value="">加载中…</option>';
      try{
        const res = await fetch('/api/discover/wireguard-interfaces?endpoint=' + encodeURIComponent(ep));
        const raw = await res.json().catch(() => ({}));
        const data = apiData(raw) || {};
        const merged = mergeWgNames(data.names, 'server', ep);
        if(res.ok){
          populateWgSelect(sel, merged, keep);
          return;
        }
        if(merged.length){
          populateWgSelect(sel, merged, keep);
          return;
        }
        sel.innerHTML = '<option value="">' + escapeHtml(apiErrorText(raw, '无法从设备加载，且无已保存的参考名称')) + '</option>';
      }catch(_e){
        const merged = mergeWgNames([], 'server', ep);
        if(merged.length){
          populateWgSelect(sel, merged, keep);
        }else{
          sel.innerHTML = '<option value="">网络错误，请检查服务后重开此窗口</option>';
        }
      }
    }
    async function loadClientWireguardOptions(preserveValue, clearSelection){
      const ep = document.getElementById('l_client_endpoint_ref').value.trim();
      const sel = document.getElementById('l_client_wireguard_name');
      const keep = clearSelection ? '' : (preserveValue !== undefined ? String(preserveValue) : sel.value);
      if(!ep){
        sel.innerHTML = '<option value="">请先选择客户端路由器</option>';
        return;
      }
      sel.innerHTML = '<option value="">加载中…</option>';
      try{
        const res = await fetch('/api/discover/wireguard-interfaces?endpoint=' + encodeURIComponent(ep));
        const raw = await res.json().catch(() => ({}));
        const data = apiData(raw) || {};
        const merged = mergeWgNames(data.names, 'client', ep);
        if(res.ok){
          populateWgSelect(sel, merged, keep);
          return;
        }
        if(merged.length){
          populateWgSelect(sel, merged, keep);
          return;
        }
        sel.innerHTML = '<option value="">' + escapeHtml(apiErrorText(raw, '无法从设备加载，且无已保存的参考名称')) + '</option>';
      }catch(_e){
        const merged = mergeWgNames([], 'client', ep);
        if(merged.length){
          populateWgSelect(sel, merged, keep);
        }else{
          sel.innerHTML = '<option value="">网络错误，请检查服务后重开此窗口</option>';
        }
      }
    }
    function statusTag(ok){
      return ok ? '<span class="chip chip-ok">正常</span>' : '<span class="chip chip-bad">异常</span>';
    }
    function formatMbps(v){
      const kbps = Number(v || 0) / 1000;
      if(kbps < 1000){
        return kbps.toFixed(2) + ' Kbps';
      }
      return (kbps / 1000).toFixed(2) + ' Mbps';
    }
    function drawMiniLines(canvas, txHistory, rxHistory){
      const ctx = canvas.getContext('2d');
      const width = canvas.width;
      const height = canvas.height;
      ctx.clearRect(0, 0, width, height);
      ctx.strokeStyle = 'rgba(255,255,255,0.08)';
      ctx.lineWidth = 1;
      [0.25, 0.5, 0.75].forEach(scale => {
        const y = height * scale;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      });
      const tx = Array.isArray(txHistory) ? txHistory : [];
      const rx = Array.isArray(rxHistory) ? rxHistory : [];
      const all = tx.concat(rx);
      const maxY = all.length ? Math.max(...all, 1) : 1;
      const drawLine = (arr, color) => {
        if(!arr.length) return;
        const step = arr.length > 1 ? width / (arr.length - 1) : width;
        ctx.beginPath();
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        arr.forEach((p, i) => {
          const x = i * step;
          const y = height - ((p / maxY) * height);
          if(i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        });
        ctx.stroke();
      };
      drawLine(tx, '#4ea1ff');
      drawLine(rx, '#30d07f');
    }
    function renderEndpointCards(rows){
      const holder = document.getElementById('endpointGrid');
      if(!rows.length){
        holder.innerHTML = '<div class="muted">暂无路由器配置</div>';
        return;
      }
      holder.innerHTML = rows.map((r) => `
        <div class="device-card">
          <div class="device-head">
            <div class="device-name">${r.name}</div>
            <button class="icon-btn" title="编辑路由器" onclick='openEndpointFromCard("${r.name}")'>⚙</button>
          </div>
          <div class="host-line">${r.host}:${r.port}</div>
          <div class="speed-grid">
            <div class="speed-box">
              <div class="speed-label">上传</div>
              <div class="speed-value">${formatMbps(r.tx_bps || 0)}</div>
            </div>
            <div class="speed-box">
              <div class="speed-label">下载</div>
              <div class="speed-value">${formatMbps(r.rx_bps || 0)}</div>
            </div>
          </div>
          <canvas class="mini-chart" id="mini-chart-${r.name.replace(/[^a-zA-Z0-9_-]/g, '_')}" width="360" height="78"></canvas>
          <div class="chart-legend">蓝线上传 / 绿线下载</div>
        </div>
      `).join('');
      rows.forEach((r) => {
        const id = `mini-chart-${String(r.name).replace(/[^a-zA-Z0-9_-]/g, '_')}`;
        const canvas = document.getElementById(id);
        if(!canvas) return;
        drawMiniLines(canvas, r.tx_history, r.rx_history);
      });
    }
    function openEndpointFromCard(name){
      const endpoint = endpointCache.find(e => e.name === name);
      if(endpoint){
        openEndpointModal(endpoint);
        return;
      }
      openEndpointModal({ name, host: '', port: 8728, username: '', password: '', display_index: 0 });
    }
    async function refreshEndpoints(){
      try{
        const res = await fetch('/api/config/endpoints');
        if(!res.ok) return;
        const rows = apiData(await res.json());
        endpointCache = Array.isArray(rows) ? rows : [];
      }catch(_e){
      }
    }
    function renderRoleEndpointOptions(){
      const serverSel = document.getElementById('l_server_endpoint_ref');
      const clientSel = document.getElementById('l_client_endpoint_ref');
      const sorted = [...endpointCache].sort((a, b) => {
        const da = Number(a.display_index ?? 0);
        const db = Number(b.display_index ?? 0);
        if(da !== db) return da - db;
        return String(a.name).localeCompare(String(b.name), 'zh-CN');
      });
      const opts = sorted.map(e => `<option value="${e.name}">${e.name}</option>`).join('') || '<option value="">无设备</option>';
      serverSel.innerHTML = opts;
      clientSel.innerHTML = opts;
    }
    function renderLinkMonitorTable(statusRows, configs){
      const tbody = document.getElementById('linkMonitorRows');
      if(!tbody) return;
      const byName = {};
      (Array.isArray(statusRows) ? statusRows : []).forEach((r) => { byName[r.name] = r; });
      const list = Array.isArray(configs) ? [...configs].sort((a, b) => String(a.name).localeCompare(String(b.name), 'zh-CN')) : [];
      if(!list.length){
        tbody.innerHTML = '<tr><td colspan="8" class="muted">暂无连接监控配置</td></tr>';
        return;
      }
      tbody.innerHTML = list.map((cfg) => {
        const r = byName[cfg.name] || {};
        const devName = cfg.client_endpoint_ref || '-';
        const srvName = cfg.server_endpoint_ref || '-';
        const ok = r.health_ok === true;
        const pl = (r.packet_loss === null || r.packet_loss === undefined)
          ? '<span class="muted">-</span>'
          : escapeHtml(String(r.packet_loss)) + '%';
        const tx = formatMbps(r.tx_bps || 0);
        const rx = formatMbps(r.rx_bps || 0);
        const last = escapeHtml(r.last_check_iso || '-');
        const nm = cfg.name;
        return `<tr>
          <td><strong>${escapeHtml(devName)}</strong></td>
          <td>${escapeHtml(srvName)}</td>
          <td class="ta-center">${statusTag(ok)}</td>
          <td class="ta-center">${pl}</td>
          <td class="ta-right">${escapeHtml(tx)}</td>
          <td class="ta-right">${escapeHtml(rx)}</td>
          <td class="muted ta-center">${last}</td>
          <td class="ta-center">
            <button type="button" class="btn btn-inline" onclick="openLinkModalByName(${JSON.stringify(nm)})">编辑</button>
            <button type="button" class="btn btn-inline btn-danger" onclick="deleteLink(${JSON.stringify(nm)})">删除</button>
          </td>
        </tr>`;
      }).join('');
    }
    async function refreshLinks(){
      try{
        const res = await fetch('/api/config/links');
        if(!res.ok) return;
        const rows = apiData(await res.json());
        linkCache = Array.isArray(rows) ? rows : [];
        renderLinkMonitorTable(lastLinkStatusRows, linkCache);
      }catch(_e){
      }
    }
    function openLinkModalByName(name){
      const item = linkCache.find((l) => l.name === name);
      if(item) openLinkModal(item);
      else openLinkModal(null);
    }
    function openEndpointModal(item){
      editingEndpointName = item ? item.name : null;
      document.getElementById('endpointModalTitle').textContent = item ? '编辑路由器' : '新增路由器';
      document.getElementById('f_name').value = item ? item.name : '';
      document.getElementById('f_name').disabled = !!item;
      document.getElementById('f_display_index').value = item && item.display_index !== undefined && item.display_index !== null ? item.display_index : 0;
      document.getElementById('f_host').value = item ? item.host : '';
      document.getElementById('f_port').value = item ? item.port : 8728;
      document.getElementById('f_username').value = item ? item.username : '';
      document.getElementById('f_password').value = item ? item.password : '';
      document.getElementById('f_wan_interface').value = item ? (item.wan_interface || '') : '';
      document.getElementById('endpointDeleteBtn').style.display = item ? 'inline-block' : 'none';
      document.getElementById('endpointModalMask').style.display = 'flex';
    }
    function closeEndpointModal(){
      document.getElementById('endpointModalMask').style.display = 'none';
      editingEndpointName = null;
    }
    async function deleteEndpointFromModal(){
      if(!editingEndpointName) return;
      if(!confirm(`确认删除路由器 ${editingEndpointName} 吗？关联 link 也会被删除`)) return;
      const res = await fetch(`/api/config/endpoints/${editingEndpointName}`, { method: 'DELETE' });
      if(!res.ok){
        let msg = await res.text();
        try{
          const parsed = JSON.parse(msg);
          if(parsed && parsed.error) msg = parsed.error;
        }catch(_e){
        }
        alert('删除失败: ' + msg);
        return;
      }
      closeEndpointModal();
      await refreshEndpoints();
      await refreshLinks();
    }
    async function saveEndpoint(){
      const payload = {
        name: document.getElementById('f_name').value.trim(),
        host: document.getElementById('f_host').value.trim(),
        port: Number(document.getElementById('f_port').value),
        username: document.getElementById('f_username').value.trim(),
        password: document.getElementById('f_password').value,
        wan_interface: document.getElementById('f_wan_interface').value.trim(),
        display_index: Number(document.getElementById('f_display_index').value) || 0
      };
      const method = editingEndpointName ? 'PUT' : 'POST';
      const url = editingEndpointName ? `/api/config/endpoints/${editingEndpointName}` : '/api/config/endpoints';
      const res = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      if(!res.ok){
        let msg = await res.text();
        try{
          const parsed = JSON.parse(msg);
          if(parsed && parsed.error) msg = parsed.error;
        }catch(_e){
        }
        alert('保存失败: ' + msg);
        return;
      }
      closeEndpointModal();
      await refreshEndpoints();
    }
    async function deleteEndpoint(name){
      if(!confirm(`确认删除路由器 ${name} 吗？关联 link 也会被删除`)) return;
      const res = await fetch(`/api/config/endpoints/${name}`, { method: 'DELETE' });
      if(!res.ok){
        let msg = await res.text();
        try{
          const parsed = JSON.parse(msg);
          if(parsed && parsed.error) msg = parsed.error;
        }catch(_e){
        }
        alert('删除失败: ' + msg);
        return;
      }
      await refreshEndpoints();
    }
    function openLinkModal(item){
      renderRoleEndpointOptions();
      editingLinkName = item ? item.name : null;
      document.getElementById('linkModalTitle').textContent = item ? '编辑连接监控' : '新增连接监控';
      document.getElementById('l_name').value = item ? item.name : '';
      document.getElementById('l_name').disabled = !!item;
      document.getElementById('l_wg_subnet').value = item ? (item.wg_subnet || '') : '';
      document.getElementById('l_server_endpoint_ref').value = item ? item.server_endpoint_ref : (document.getElementById('l_server_endpoint_ref').value || '');
      document.getElementById('l_client_endpoint_ref').value = item ? item.client_endpoint_ref : (document.getElementById('l_client_endpoint_ref').value || '');
      document.getElementById('linkModalMask').style.display = 'flex';
      const swg = item ? (item.server_wireguard_name || '') : '';
      const cwg = item ? (item.client_wireguard_name || '') : '';
      Promise.all([loadServerWireguardOptions(swg, false), loadClientWireguardOptions(cwg, false)]);
    }
    function closeLinkModal(){
      document.getElementById('linkModalMask').style.display = 'none';
      editingLinkName = null;
    }
    async function saveLink(){
      const sWg = document.getElementById('l_server_wireguard_name').value.trim();
      const cWg = document.getElementById('l_client_wireguard_name').value.trim();
      if(!sWg || !cWg){
        alert('请在「服务器 / 客户端 WG 连接名称」下拉框中各选择一个 WireGuard 接口。');
        return;
      }
      const payload = {
        name: document.getElementById('l_name').value.trim(),
        wg_subnet: document.getElementById('l_wg_subnet').value.trim(),
        server_endpoint_ref: document.getElementById('l_server_endpoint_ref').value.trim(),
        server_wireguard_name: sWg,
        client_endpoint_ref: document.getElementById('l_client_endpoint_ref').value.trim(),
        client_wireguard_name: cWg,
      };
      const method = editingLinkName ? 'PUT' : 'POST';
      const url = editingLinkName ? `/api/config/links/${editingLinkName}` : '/api/config/links';
      const res = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      if(!res.ok){
        let msg = await res.text();
        try{
          const parsed = JSON.parse(msg);
          if(parsed && parsed.error) msg = parsed.error;
        }catch(_e){
        }
        alert('保存连接监控失败: ' + msg);
        return;
      }
      closeLinkModal();
      await refreshLinks();
    }
    async function deleteLink(name){
      if(!confirm(`确认删除连接监控 ${name} 吗？`)) return;
      const res = await fetch(`/api/config/links/${name}`, { method: 'DELETE' });
      if(!res.ok){
        let msg = await res.text();
        try{
          const parsed = JSON.parse(msg);
          if(parsed && parsed.error) msg = parsed.error;
        }catch(_e){
        }
        alert('删除连接监控失败: ' + msg);
        return;
      }
      await refreshLinks();
    }
    async function refresh(){
      try{
        const [resStatus, resRouters, resEndpoints, resLinks] = await Promise.all([
          fetch('/api/status'),
          fetch('/api/routers-status'),
          fetch('/api/config/endpoints'),
          fetch('/api/config/links'),
        ]);
        const rows = apiData(await resStatus.json());
        const routerRows = apiData(await resRouters.json());
        const endpoints = apiData(await resEndpoints.json());
        const linkCfgs = apiData(await resLinks.json());
        if(Array.isArray(endpoints)){
          endpointCache = endpoints;
        }
        if(Array.isArray(linkCfgs)){
          linkCache = linkCfgs;
        }
        lastLinkStatusRows = rows;
        renderLinkMonitorTable(rows, linkCache);

        const linkTotal = rows.length;
        const ok = rows.filter(r => r.health_ok).length;
        const bad = linkTotal - ok;
        const circuit = rows.filter(r => r.circuit_open).length;
        document.getElementById('totalCount').textContent = Array.isArray(endpoints) ? endpoints.length : 0;
        document.getElementById('okCount').textContent = ok;
        document.getElementById('badCount').textContent = bad;
        document.getElementById('circuitCount').textContent = circuit;
        renderEndpointCards(routerRows);
      }catch(err){
        const tbody = document.getElementById('linkMonitorRows');
        if(tbody){
          tbody.innerHTML = '<tr><td colspan="8" class="bad-text">状态加载失败，请稍后重试</td></tr>';
        }
        console.error('refresh failed:', err);
      }
    }
    async function logout(){
      await fetch('/api/logout', { method: 'POST' });
      location.href = '/login';
    }
    refresh();
    refreshEndpoints();
    refreshLinks();
    setInterval(refresh, 5000);
  </script>
</body>
</html>
"""


def _login_page() -> str:
    return """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mikrotik 登录</title>
  <style>
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; font-family: Arial, sans-serif; background: #0b1220; color: #e6ecff; }
    .box { width: min(420px, 92vw); background: #111a2e; border: 1px solid #243458; border-radius: 12px; padding: 18px; }
    .title { margin: 0 0 12px; font-size: 20px; }
    .hint { color: #98a4c7; font-size: 13px; margin-bottom: 10px; }
    input { width: 100%; box-sizing: border-box; padding: 10px; border-radius: 8px; border: 1px solid #243458; background: #0f1830; color: #e6ecff; }
    button { margin-top: 10px; width: 100%; padding: 10px; border-radius: 8px; border: 1px solid #243458; background: #213056; color: #e6ecff; cursor: pointer; }
    #msg { min-height: 20px; margin-top: 8px; color: #ff8f8f; font-size: 13px; }
  </style>
</head>
<body>
  <div class="box">
    <h1 class="title">系统登录</h1>
    <div class="hint">请输入访问密码</div>
    <input id="pwd" type="password" placeholder="密码" />
    <button onclick="login()">登录</button>
    <div id="msg"></div>
  </div>
  <script>
    async function login(){
      const password = document.getElementById('pwd').value;
      const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ password }) });
      const payload = await res.json().catch(() => ({}));
      if(!res.ok || payload.ok !== true){
        document.getElementById('msg').textContent = (payload && payload.error) || '登录失败';
        return;
      }
      location.href = '/';
    }
  </script>
</body>
</html>
"""


def build_handler(store: StatusStore, config_store: RuntimeConfigStore, reload_config_callback):
    sessions: set[str] = set()

    class Handler(BaseHTTPRequestHandler):
        def _write(self, code: int, content_type: str, body: str) -> None:
            payload = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _write_ok(self, data=None) -> None:
            self._write(200, "application/json; charset=utf-8", json.dumps({"ok": True, "data": data}, ensure_ascii=False))

        def _write_error(self, code: int, error: str, error_code: str = "bad_request") -> None:
            self._write(
                code,
                "application/json; charset=utf-8",
                json.dumps({"ok": False, "error_code": error_code, "error": error}, ensure_ascii=False),
            )

        def _read_json(self):
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                return {}
            raw = self.rfile.read(content_length).decode("utf-8")
            return json.loads(raw)

        def _web_password(self) -> str:
            password, _ = config_store.ensure_web_password()
            return password

        def _session_token(self) -> str:
            raw = self.headers.get("Cookie", "")
            if not raw:
                return ""
            jar = cookies.SimpleCookie()
            try:
                jar.load(raw)
            except Exception:
                return ""
            morsel = jar.get("mt_session")
            return morsel.value if morsel else ""

        def _is_authenticated(self) -> bool:
            return self._session_token() in sessions

        def _set_session_cookie_header(self) -> None:
            token = secrets.token_urlsafe(24)
            sessions.add(token)
            self.send_header("Set-Cookie", f"mt_session={token}; Path=/; HttpOnly; SameSite=Lax")

        def _clear_session_cookie_header(self) -> None:
            token = self._session_token()
            if token in sessions:
                sessions.remove(token)
            self.send_header("Set-Cookie", "mt_session=deleted; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")

        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)
            if self.path == "/login":
                if self._is_authenticated():
                    self.send_response(302)
                    self.send_header("Location", "/")
                    self.end_headers()
                    return
                self._write(200, "text/html; charset=utf-8", _login_page())
                return
            if self.path in ("/", "/index.html"):
                if not self._is_authenticated():
                    self.send_response(302)
                    self.send_header("Location", "/login")
                    self.end_headers()
                    return
                self._write(200, "text/html; charset=utf-8", _html_page())
                return
            if parsed.path.startswith("/api/") and parsed.path != "/api/login" and parsed.path != "/healthz":
                if not self._is_authenticated():
                    self._write_error(401, "请先登录", "unauthorized")
                    return
            if self.path == "/api/status":
                self._write_ok(store.snapshot())
                return
            if self.path == "/api/routers-status":
                self._write_ok(json.loads(_serialize_routers_status(store, config_store)))
                return
            if parsed.path == "/api/config/endpoints":
                self._write_ok(config_store.list_endpoints())
                return
            if parsed.path == "/api/config/links":
                self._write_ok(config_store.list_links())
                return
            if parsed.path == "/api/config/settings":
                self._write_ok(config_store.get_settings())
                return
            if parsed.path == "/api/config/yaml":
                self._write_ok({"text": config_store.read_yaml_text()})
                return
            if parsed.path == "/api/discover/wireguard-interfaces":
                qs = parse_qs(parsed.query or "")
                endpoint = (qs.get("endpoint") or [""])[0].strip()
                try:
                    names = list_wireguard_interface_names(config_store, endpoint)
                    self._write_ok({"names": names})
                except ValueError as exc:
                    self._write_error(400, str(exc), "validation_error")
                except RouterOsError as exc:
                    self._write_error(502, str(exc), "routeros_error")
                except Exception as exc:  # noqa: BLE001
                    self._write_error(500, str(exc), "internal_error")
                return
            if self.path == "/healthz":
                self._write(200, "application/json; charset=utf-8", '{"ok": true}')
                return
            self._write(404, "text/plain; charset=utf-8", "not found")

        def do_POST(self):  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/api/login":
                try:
                    payload = self._read_json()
                    if str(payload.get("password", "")) != self._web_password():
                        self._write_error(401, "密码错误", "invalid_password")
                        return
                    self.send_response(200)
                    self._set_session_cookie_header()
                    body = json.dumps({"ok": True, "data": None}, ensure_ascii=False).encode("utf-8")
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except Exception as exc:
                    self._write_error(400, str(exc), "validation_error")
                return
            if parsed.path == "/api/logout":
                self.send_response(200)
                self._clear_session_cookie_header()
                body = b'{"ok": true, "data": null}'
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if parsed.path.startswith("/api/") and not self._is_authenticated():
                self._write_error(401, "请先登录", "unauthorized")
                return
            if parsed.path == "/api/config/endpoints":
                try:
                    payload = self._read_json()
                    _validate_endpoint_payload(payload)
                    config_store.upsert_endpoint(payload)
                    reload_config_callback()
                    self._write_ok(None)
                except Exception as exc:
                    self._write_error(400, str(exc), "validation_error")
                return
            if parsed.path == "/api/config/links":
                try:
                    payload = self._read_json()
                    _validate_link_payload(payload)
                    config_store.upsert_link(payload)
                    reload_config_callback()
                    self._write_ok(None)
                except Exception as exc:
                    self._write_error(400, str(exc), "validation_error")
                return
            self._write(404, "text/plain; charset=utf-8", "not found")
            return

        def do_PUT(self):  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path.startswith("/api/") and not self._is_authenticated():
                self._write_error(401, "请先登录", "unauthorized")
                return
            if parsed.path.startswith("/api/config/endpoints/"):
                name = parsed.path.split("/api/config/endpoints/", 1)[1].strip()
                try:
                    payload = self._read_json()
                    payload["name"] = name
                    _validate_endpoint_payload(payload)
                    config_store.upsert_endpoint(payload)
                    reload_config_callback()
                    self._write_ok(None)
                except Exception as exc:
                    self._write_error(400, str(exc), "validation_error")
                return
            if parsed.path.startswith("/api/config/links/"):
                name = parsed.path.split("/api/config/links/", 1)[1].strip()
                try:
                    payload = self._read_json()
                    payload["name"] = name
                    _validate_link_payload(payload)
                    config_store.upsert_link(payload)
                    reload_config_callback()
                    self._write_ok(None)
                except Exception as exc:
                    self._write_error(400, str(exc), "validation_error")
                return
            if parsed.path == "/api/config/settings":
                try:
                    payload = self._read_json()
                    _validate_settings_payload(payload)
                    config_store.update_settings(payload)
                    reload_config_callback()
                    self._write_ok(None)
                except Exception as exc:
                    self._write_error(400, str(exc), "validation_error")
                return
            if parsed.path == "/api/config/yaml":
                try:
                    payload = self._read_json()
                    text = str(payload.get("text", ""))
                    if not text.strip():
                        raise ValueError("YAML 内容不能为空")
                    config_store.write_yaml_text(text)
                    reload_config_callback()
                    self._write_ok(None)
                except Exception as exc:
                    self._write_error(400, str(exc), "validation_error")
                return
            self._write(404, "text/plain; charset=utf-8", "not found")

        def do_DELETE(self):  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path.startswith("/api/") and not self._is_authenticated():
                self._write_error(401, "请先登录", "unauthorized")
                return
            if parsed.path.startswith("/api/config/endpoints/"):
                name = parsed.path.split("/api/config/endpoints/", 1)[1].strip()
                try:
                    config_store.delete_endpoint(name)
                    reload_config_callback()
                    self._write_ok(None)
                except Exception as exc:
                    self._write_error(400, str(exc), "validation_error")
                return
            if parsed.path.startswith("/api/config/links/"):
                name = parsed.path.split("/api/config/links/", 1)[1].strip()
                try:
                    config_store.delete_link(name)
                    reload_config_callback()
                    self._write_ok(None)
                except Exception as exc:
                    self._write_error(400, str(exc), "validation_error")
                return
            self._write(404, "text/plain; charset=utf-8", "not found")

        def log_message(self, format, *args):  # noqa: A003
            return

    return Handler


def start_web_server(
    status_store: StatusStore,
    config_store: RuntimeConfigStore,
    reload_config_callback,
    host: str,
    port: int,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), build_handler(status_store, config_store, reload_config_callback))
    thread = Thread(target=server.serve_forever, daemon=True, name="status-web-server")
    thread.start()
    return server
