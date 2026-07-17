# Xray Manager

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

Open http://localhost:65000

The app image is published as [`mparvin/xray-manager:latest`](https://hub.docker.com/r/mparvin/xray-manager).

### Option B — Run Flask directly

```bash
pip install -r requirements.txt
python app.py
# then start the Xray container separately:
docker compose up -d xray
```

## Architecture

All proxies share **a single Xray container** (`teddysun/xray:26.6.1`).
`configs/config.json` holds every proxy as a separate **inbound + outbound pair** connected by a routing rule.

When a proxy is deployed or removed the Flask app:
1. Updates `configs/config.json` (adds/removes the inbound, outbound, and routing rule)
2. Sends **SIGHUP** to the Xray process — hot-reloads the config with **zero downtime** for other proxies

A combined SOCKS proxy on **port 1080** routes traffic through all deployed proxies using Xray's **leastPing** balancer and observatory health checks.

## Features

- **Parse**: Paste any raw text (Telegram message, config list, etc.) — the app extracts all `ss://`, `vmess://`, `vless://`, and `trojan://` URIs automatically
- **Preview & Select**: Review extracted proxies and select which ones to deploy
- **Deploy**: Each selected proxy gets:
  - An inbound entry (SOCKS5, unique port 62500–62999) added to `configs/config.json`
  - A matching outbound + routing rule added in the same file
  - Xray config hot-reloaded via SIGHUP (no container restart)
- **Combined proxy**: SOCKS5 on port **1080** with leastPing load balancing across all proxies
- **Status Panel**: Live status of all configured proxies with auto-refresh every 15s
- **Reload button**: Manually send SIGHUP to hot-reload Xray config
- **Remove**: Per-proxy removal — updates config and hot-reloads Xray
- **Bulk actions**: Remove duplicates, remove not-working proxies, export all configs

## Port Range

| Port | Purpose |
|------|---------|
| `1080` | Combined SOCKS proxy (leastPing across all proxies) |
| `62500–62999` | Per-proxy SOCKS5 inbounds |
| `65000` | Xray Manager web UI (Docker Compose default) |

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

## CI / Docker Hub

Pushes to `main` and version tags (`v*`) build and publish the app image to Docker Hub.

**Repository:** `mparvin/xray-manager`

**Required GitHub secrets:**

| Secret | Value |
|--------|-------|
| `DOCKERHUB_USERNAME` | `mparvin` |
| `DOCKERHUB_TOKEN` | Docker Hub access token |

## Proxy Protocol Support

| Protocol     | Outbound Config |
|-------------|----------------|
| `vmess://`  | VMess with TCP/WebSocket, optional TLS |
| `vless://`  | VLess with Reality/TLS/plain |
| `ss://`     | Shadowsocks (chacha20, aes-128-gcm, etc.) |
| `trojan://` | Trojan with TLS |

All proxies run inside a single `teddysun/xray:26.6.1` container.


## Todo

[ ] Add shadowsocks support
[ ] Add suport of disabling multiple port listening, and just use the balancer config
[ ] Add trojan config support
[ ] Add connection time in mili seconds for each configuration
[ ] Add support of JSON configurations import, example of configuration in JSON:
```

{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "hosts": {
      "dns.google": [
        "8.8.8.8",
        "8.8.4.4",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844"
      ],
      "dns.alidns.com": [
        "223.5.5.5",
        "223.6.6.6",
        "2400:3200::1",
        "2400:3200:baba::1"
      ],
      "one.one.one.one": [
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001"
      ],
      "1dot1dot1dot1.cloudflare-dns.com": [
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001"
      ],
      "cloudflare-dns.com": [
        "104.16.249.249",
        "104.16.248.249",
        "2606:4700::6810:f8f9",
        "2606:4700::6810:f9f9"
      ],
      "dns.cloudflare.com": [
        "104.16.132.229",
        "104.16.133.229",
        "2606:4700::6810:84e5",
        "2606:4700::6810:85e5"
      ],
      "dot.pub": [
        "1.12.12.12",
        "120.53.53.53"
      ],
      "doh.pub": [
        "1.12.12.12",
        "120.53.53.53"
      ],
      "dns.quad9.net": [
        "9.9.9.9",
        "149.112.112.112",
        "2620:fe::fe",
        "2620:fe::9"
      ],
      "dns.yandex.net": [
        "77.88.8.8",
        "77.88.8.1",
        "2a02:6b8::feed:0ff",
        "2a02:6b8:0:1::feed:0ff"
      ],
      "dns.sb": [
        "185.222.222.222",
        "2a09::"
      ],
      "dns.umbrella.com": [
        "208.67.220.220",
        "208.67.222.222",
        "2620:119:35::35",
        "2620:119:53::53"
      ],
      "dns.sse.cisco.com": [
        "208.67.220.220",
        "208.67.222.222",
        "2620:119:35::35",
        "2620:119:53::53"
      ],
      "engage.cloudflareclient.com": [
        "162.159.192.1"
      ]
    },
    "servers": [
      {
        "address": "https://dns.alidns.com/dns-query",
        "domains": [
          "domain:alidns.com",
          "domain:doh.pub",
          "domain:dot.pub",
          "domain:360.cn",
          "domain:onedns.net"
        ],
        "skipFallback": true,
        "tag": "direct-dns-1"
      },
      {
        "address": "https://cloudflare-dns.com/dns-query",
        "domains": [
          "geosite:google"
        ],
        "skipFallback": true
      },
      {
        "address": "https://dns.alidns.com/dns-query",
        "domains": [
          "geosite:private",
          "geosite:cn"
        ],
        "skipFallback": true,
        "tag": "direct-dns-2"
      },
      {
        "address": "223.5.5.5",
        "domains": [
          "full:dns.alidns.com",
          "full:cloudflare-dns.com"
        ],
        "skipFallback": true
      },
      "https://cloudflare-dns.com/dns-query"
    ],
    "tag": "dns-module"
  },
  "inbounds": [
    {
      "tag": "socks",
      "port": 10808,
      "listen": "127.0.0.1",
      "protocol": "mixed",
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "routeOnly": false
      },
      "settings": {
        "auth": "noauth",
        "udp": true,
        "allowTransparent": false
      }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "188.114.97.4",
            "port": 443,
            "users": [
              {
                "id": "d171491a-9995-46ce-8719-f64463ca3a45",
                "email": "t@t.tt",
                "security": "auto",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": false,
          "serverName": "sertraline.adaspoloandco.com",
          "alpn": [
            "http/1.1",
            "h2"
          ],
          "fingerprint": "chrome"
        },
        "wsSettings": {
          "path": "/download.php",
          "host": "sertraline.adaspoloandco.com",
          "headers": {}
        }
      },
      "mux": {
        "enabled": false,
        "concurrency": -1
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom"
    },
    {
      "tag": "block",
      "protocol": "blackhole"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api"
      },
      {
        "type": "field",
        "port": "443",
        "network": "udp",
        "outboundTag": "block"
      },
      {
        "type": "field",
        "outboundTag": "proxy",
        "domain": [
          "geosite:google"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": [
          "geoip:private"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "geosite:private"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": [
          "223.5.5.5",
          "223.6.6.6",
          "2400:3200::1",
          "2400:3200:baba::1",
          "119.29.29.29",
          "1.12.12.12",
          "120.53.53.53",
          "2402:4e00::",
          "2402:4e00:1::",
          "180.76.76.76",
          "2400:da00::6666",
          "114.114.114.114",
          "114.114.115.115",
          "114.114.114.119",
          "114.114.115.119",
          "114.114.114.110",
          "114.114.115.110",
          "180.184.1.1",
          "180.184.2.2",
          "101.226.4.6",
          "218.30.118.6",
          "123.125.81.6",
          "140.207.198.6",
          "1.2.4.8",
          "210.2.4.8",
          "52.80.66.66",
          "117.50.22.22",
          "2400:7fc0:849e:200::4",
          "2404:c2c0:85d8:901::4",
          "117.50.10.10",
          "52.80.52.52",
          "2400:7fc0:849e:200::8",
          "2404:c2c0:85d8:901::8",
          "117.50.60.30",
          "52.80.60.30"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "domain:alidns.com",
          "domain:doh.pub",
          "domain:dot.pub",
          "domain:360.cn",
          "domain:onedns.net"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": [
          "geoip:cn"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "geosite:cn"
        ]
      },
      {
        "type": "field",
        "inboundTag": [
          "direct-dns-1",
          "direct-dns-2"
        ],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "inboundTag": [
          "dns-module"
        ],
        "outboundTag": "proxy"
      }
    ]
  }
}
```

[ ] Add subscriptions import, it should gets subscriptions URLs and import them, user should puts the subscriptions url in the same box that puts VLESS and VMESS configurations. sometime subscription list should hashed by base64.
example of subscriptions list:
```
curl -SsL https://raw.githubusercontent.com/ThomasJasperthecat/sub/main/sublist1.txt

dmxlc3M6Ly9kMTcxNDkxYS05OTk1LTQ2Y2UtODcxOS1mNjQ0NjNjYTNhNDVAMTg4LjExNC45Ny40OjQ0Mz90eXBlPXdzJmVuY3J5cHRpb249bm9uZSZwYXRoPSUyRmRvd25sb2FkLnBocCZob3N0PXNlcnRyYWxpbmUuYWRhc3BvbG9hbmRjby5jb20mc2VjdXJpdHk9dGxzJmZwPWNocm9tZSZhbHBuPWh0dHAlMkYxLjElMkNoMiZzbmk9c2VydHJhbGluZS5hZGFzcG9sb2FuZGNvLmNvbSNTZXJ0cmFsaW5lLUZpbmxhbmQtYzIwDQp2bGVzczovL2Y3OThhMmM0LWM1MWItNDA5ZC1iMzQ5LWNhODQ1NWIzNjc5NkAxODguMTE0Ljk3LjQ6ODQ0Mz90eXBlPXdzJmVuY3J5cHRpb249bm9uZSZwYXRoPSUyRmRvd25sb2FkLnBocCZob3N0PWNob3Bpbi5hZGFzcG9sb2FuZGNvLmNvbSZzZWN1cml0eT10bHMmZnA9Y2hyb21lJmFscG49aDIlMkNodHRwJTJGMS4xJnNuaT1jaG9waW4uYWRhc3BvbG9hbmRjby5jb20jY2hwb2luLXBvbGFuZC1jMjANCnZsZXNzOi8vZmVjNzAzNzUtMjljZi00NmNmLWIzMTQtNTM2Yzc0ZmVlZTk0QDE4OC4xMTQuOTcuNDo4NDQzP3R5cGU9d3MmZW5jcnlwdGlvbj1ub25lJnBhdGg9JTJGYWRtaW4ucGhwJmhvc3Q9cmF0YXRvdWlsbGUuYWRhc3BvbG9hbmRjby5jb20mc2VjdXJpdHk9dGxzJmZwPWNocm9tZSZhbHBuPWgyJTJDaHR0cCUyRjEuMSZzbmk9cmF0YXRvdWlsbGUuYWRhc3BvbG9hbmRjby5jb20jcmF0YXRvdWlsbGUtZnJhbmNlLWMyMA0Kdmxlc3M6Ly81Nzc2OTlmNy00NjhkLTRiNjMtYWUyMS1jZGNkZmQ4ZDExYzJAMTg4LjExNC45Ny40OjQ0Mz90eXBlPXdzJmVuY3J5cHRpb249bm9uZSZwYXRoPSUyRkdvb3JCYWgmaG9zdD1iYWd1ZXR0ZS5hZGFzcG9sb2FuZGNvLmNvbSZzZWN1cml0eT10bHMmZnA9Y2hyb21lJmFscG49aDIlMkNodHRwJTJGMS4xJnNuaT1iYWd1ZXR0ZS5hZGFzcG9sb2FuZGNvLmNvbSNCYWd1ZXR0ZS1GcmFuY2UtYzIwDQp2bGVzczovL2RiM2YwOWFlLTIzZjItNDJiOC1hYmVlLTdiODlmYjM5MmM1ZUAxODguMTE0Ljk3LjQ6ODQ0Mz90eXBlPXdzJmVuY3J5cHRpb249bm9uZSZwYXRoPSUyRnVwbG9hZGVyLnBocCZob3N0PW1hcGxlLmFkYXNwb2xvYW5kY28uY29tJnNlY3VyaXR5PXRscyZmcD1jaHJvbWUmYWxwbj1oMiUyQ2h0dHAlMkYxLjEmc25pPW1hcGxlLmFkYXNwb2xvYW5kY28uY29tI21hcGxlLWNhbmFkYS1jMjANCnZsZXNzOi8vZWY2NmYyNTctMjE4Ny00OGEwLWFlNDYtZmJkMDUxOWQyNGFiQDE4OC4xMTQuOTcuNDo4NDQzP3R5cGU9d3MmZW5jcnlwdGlvbj1ub25lJnBhdGg9JTJGUml6WnJBY0smaG9zdD1mb2NhbGluLmFkYXNwb2xvYW5kY28uY29tJnNlY3VyaXR5PXRscyZmcD1jaHJvbWUmYWxwbj1oMiUyQ2h0dHAlMkYxLjEmc25pPWZvY2FsaW4uYWRhc3BvbG9hbmRjby5jb20jRm9jYWxpbi1GaW5sYW5kLWMyMA0Kdmxlc3M6Ly85N2VhNzNiNi0yMDQzLTQyMzgtOTAzYy1hMWUzZDRhNDNjOTZAMTg4LjExNC45Ny40OjIwODc/dHlwZT13cyZlbmNyeXB0aW9uPW5vbmUmcGF0aD0lMkZkb3dubG9hZC5waHAmaG9zdD1hbXBoZXRhbWluZS5hZGFzcG9sb2FuZGNvLmNvbSZzZWN1cml0eT10bHMmZnA9ZmlyZWZveCZhbHBuPWgyJTJDaHR0cCUyRjEuMSZzbmk9YW1waGV0YW1pbmUuYWRhc3BvbG9hbmRjby5jb20jYW1waGV0YW1pbmUtRmlubGFuZC1jMjANCnZsZXNzOi8vY2YzOWZhYjAtYmI4NS00MmNiLTk5NDUtMmFkNjlkNzhlNTc1QDE4OC4xMTQuOTcuNDo0NDM//
```

[ ] Add API
[ ] Add Swagger
