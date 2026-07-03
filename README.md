# XRay Proxy Manager

A Flask web app to parse and deploy V2Ray/Xray proxy configurations into a single Xray Docker container using multiple inbounds — one SOCKS5 port per proxy, all within one container.

## Requirements

- Python 3.11+
- Docker + Docker Compose v2 (`docker compose` command)
- The Docker socket accessible to the running user (for SIGHUP hot-reload)

## Setup

### Option A — Docker Compose (recommended)

```bash
docker compose up -d
```

Open http://localhost:5000

### Option B — Run Flask directly

```bash
pip install -r requirements.txt
python app.py
# then start the Xray container separately:
docker compose up -d xray
```

## Architecture

All proxies share **a single Xray container** (`teddysun/xray:26.6.1`) running with `network_mode: host`.  
`configs/config.json` holds every proxy as a separate **inbound + outbound pair** connected by a routing rule.

When a proxy is deployed or removed the Flask app:
1. Updates `configs/config.json` (adds/removes the inbound, outbound, and routing rule)
2. Sends **SIGHUP** to the Xray process — hot-reloads the config with **zero downtime** for other proxies

## Features

- **Parse**: Paste any raw text (Telegram message, config list, etc.) — the app extracts all `ss://`, `vmess://`, `vless://`, and `trojan://` URIs automatically
- **Preview & Select**: Review extracted proxies and select which ones to deploy
- **Deploy**: Each selected proxy gets:
  - An inbound entry (SOCKS5, unique port 62500–62999) added to `configs/config.json`
  - A matching outbound + routing rule added in the same file
  - Xray config hot-reloaded via SIGHUP (no container restart)
- **Status Panel**: Live status of all configured proxies with auto-refresh every 15s
- **Reload button**: Manually send SIGHUP to hot-reload Xray config
- **Remove**: Per-proxy removal — updates config and hot-reloads Xray

## Port Range

Each proxy listens on a unique SOCKS5 port in the range **62500–62999**, bound directly to the host via `network_mode: host`.

## Xray Config Structure

`configs/config.json` is managed automatically and looks like:

```json
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "inbound-abc12345",
      "port": 62500,
      "listen": "0.0.0.0",
      "protocol": "socks",
      "settings": { "auth": "noauth", "udp": true }
    }
  ],
  "outbounds": [
    {
      "tag": "outbound-abc12345",
      "protocol": "vmess",
      "settings": { "vnext": [{ "address": "...", "port": 443, "users": [...] }] }
    },
    { "protocol": "freedom", "tag": "direct" }
  ],
  "routing": {
    "rules": [
      { "type": "field", "inboundTag": ["inbound-abc12345"], "outboundTag": "outbound-abc12345" }
    ]
  }
}
```

## Docker Compose

```bash
docker compose up -d          # start everything
docker compose logs xray -f   # follow Xray logs
docker compose restart xray   # full restart (if SIGHUP is not enough)
```

## Proxy Protocol Support

| Protocol     | Outbound Config |
|-------------|----------------|
| `vmess://`  | VMess with TCP/WebSocket, optional TLS |
| `vless://`  | VLess with Reality/TLS/plain |
| `ss://`     | Shadowsocks (chacha20, aes-128-gcm, etc.) |
| `trojan://` | Trojan with TLS |

All proxies run inside a single `teddysun/xray:26.6.1` container.
