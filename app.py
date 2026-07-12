import re
import json
import uuid
import base64
import http.client
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import unquote

import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

CONFIGS_DIR = Path("configs")
CONFIG_FILE = CONFIGS_DIR / "config.json"
XRAY_CONTAINER = "xray"
PORT_START = 62500
PORT_END = 62999
PROXY_CONNECT_HOST = os.environ.get("PROXY_CONNECT_HOST", "127.0.0.1")
IP_API_URL = "http://ip-api.com/json/?fields=status,country,countryCode,query"
GEO_CACHE_TTL = 3600
_geo_cache: dict[int, tuple[float, dict]] = {}

CONFIGS_DIR.mkdir(exist_ok=True)

EMPTY_CONFIG: dict = {
    "log": {"loglevel": "warning"},
    "inbounds": [],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    "routing": {"rules": []},
}


# ─── Proxy Parsers ──────────────────────────────────────────────────────────

def parse_ss(uri: str) -> dict | None:
    """Parse shadowsocks URI: ss://BASE64@host:port#name"""
    try:
        uri = uri.strip()
        without_scheme = uri[5:]  # remove ss://
        # strip fragment
        if "#" in without_scheme:
            without_scheme = without_scheme[:without_scheme.index("#")]
        # strip query
        if "?" in without_scheme:
            without_scheme = without_scheme[:without_scheme.index("?")]

        if "@" in without_scheme:
            b64_part, hostport = without_scheme.rsplit("@", 1)
        else:
            # entire thing is base64
            decoded = base64.b64decode(without_scheme + "==").decode()
            method_pass, hostport = decoded.rsplit("@", 1)
            method, password = method_pass.split(":", 1)
            host, port = hostport.rsplit(":", 1)
            return {"protocol": "shadowsocks", "method": method, "password": password,
                    "host": host, "port": int(port)}

        try:
            decoded = base64.b64decode(b64_part + "==").decode()
            method, password = decoded.split(":", 1)
        except Exception:
            method, password = b64_part.split(":", 1)

        host, port = hostport.rsplit(":", 1)
        return {"protocol": "shadowsocks", "method": method, "password": password,
                "host": host, "port": int(port)}
    except Exception:
        return None


def parse_vmess(uri: str) -> dict | None:
    """Parse vmess URI: vmess://BASE64"""
    try:
        b64 = uri[8:]  # remove vmess://
        # add padding
        b64 += "=" * (-len(b64) % 4)
        data = json.loads(base64.b64decode(b64).decode())
        return {
            "protocol": "vmess",
            "host": data.get("add", ""),
            "port": int(data.get("port", 443)),
            "uuid": data.get("id", ""),
            "alter_id": int(data.get("aid", 0)),
            "security": data.get("scy", "auto"),
            "network": data.get("net", "tcp"),
            "tls": data.get("tls", ""),
            "path": data.get("path", ""),
            "ps": data.get("ps", ""),
        }
    except Exception:
        return None


def parse_vless(uri: str) -> dict | None:
    """Parse vless URI: vless://uuid@host:port?params#name"""
    try:
        without_scheme = uri[8:]  # remove vless://
        if "#" in without_scheme:
            without_scheme = without_scheme[:without_scheme.index("#")]

        uid_hostport, _, params_str = without_scheme.partition("?")
        uid, _, hostport = uid_hostport.partition("@")
        host, port = hostport.rsplit(":", 1)

        params = {}
        if params_str:
            for kv in params_str.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    params[k] = unquote(v)

        return {
            "protocol": "vless",
            "uuid": uid,
            "host": host,
            "port": int(port),
            "encryption": params.get("encryption", "none"),
            "flow": params.get("flow", ""),
            "security": params.get("security", "none"),
            "sni": params.get("sni", ""),
            "fp": params.get("fp", ""),
            "pbk": params.get("pbk", ""),
            "sid": params.get("sid", ""),
            "network": params.get("type", "tcp"),
        }
    except Exception:
        return None


def parse_trojan(uri: str) -> dict | None:
    """Parse trojan URI: trojan://password@host:port?params#name"""
    try:
        without_scheme = uri[9:]
        if "#" in without_scheme:
            without_scheme = without_scheme[:without_scheme.index("#")]

        password_hostport, _, params_str = without_scheme.partition("?")
        password, _, hostport = password_hostport.partition("@")
        host, port = hostport.rsplit(":", 1)

        params = {}
        if params_str:
            for kv in params_str.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    params[k] = unquote(v)

        return {
            "protocol": "trojan",
            "password": unquote(password),
            "host": host,
            "port": int(port),
            "sni": params.get("sni", host),
            "network": params.get("type", "tcp"),
        }
    except Exception:
        return None


def extract_proxies(text: str) -> list[dict]:
    """Extract all proxy URIs from raw text and parse them."""
    patterns = {
        "ss": r'ss://[^\s<>"\']+',
        "vmess": r'vmess://[^\s<>"\']+',
        "vless": r'vless://[^\s<>"\']+',
        "trojan": r'trojan://[^\s<>"\']+',
    }

    proxies = []
    seen_uris = set()

    for proto, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            uri = match.group(0).rstrip(")")  # strip trailing paren from markdown links
            if uri in seen_uris:
                continue
            seen_uris.add(uri)

            parsed = None
            if proto == "ss":
                parsed = parse_ss(uri)
            elif proto == "vmess":
                parsed = parse_vmess(uri)
            elif proto == "vless":
                parsed = parse_vless(uri)
            elif proto == "trojan":
                parsed = parse_trojan(uri)

            if parsed:
                parsed["uri"] = uri
                parsed["id"] = str(uuid.uuid4())[:8]
                proxies.append(parsed)

    # Drop duplicates that differ only by URI formatting / fragment
    unique: list[dict] = []
    seen_fps: set[tuple] = set()
    for proxy in proxies:
        fp = proxy_fingerprint(proxy)
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        unique.append(proxy)
    return unique


def proxy_fingerprint(proxy: dict) -> tuple:
    """Identity key for a proxy based on protocol + endpoint + credentials."""
    proto = proxy.get("protocol", "")
    host = str(proxy.get("host", "")).lower()
    try:
        port = int(proxy.get("port", 0))
    except (TypeError, ValueError):
        port = 0

    if proto in ("vmess", "vless"):
        return (proto, host, port, proxy.get("uuid", ""))
    if proto == "shadowsocks":
        return (proto, host, port, proxy.get("method", ""), proxy.get("password", ""))
    if proto == "trojan":
        return (proto, host, port, proxy.get("password", ""))
    return (proto, host, port)


def outbound_fingerprint(ob: dict) -> tuple | None:
    """Identity key derived from an existing Xray outbound entry."""
    proto = ob.get("protocol")
    if not proto or proto == "freedom":
        return None

    settings = ob.get("settings", {})
    if proto in ("vmess", "vless"):
        servers = settings.get("vnext", [])
        if not servers:
            return None
        server = servers[0]
        users = server.get("users") or [{}]
        return (
            proto,
            str(server.get("address", "")).lower(),
            int(server.get("port", 0) or 0),
            users[0].get("id", ""),
        )

    if proto in ("shadowsocks", "trojan"):
        servers = settings.get("servers", [])
        if not servers:
            return None
        server = servers[0]
        host = str(server.get("address", "")).lower()
        port = int(server.get("port", 0) or 0)
        if proto == "shadowsocks":
            return (proto, host, port, server.get("method", ""), server.get("password", ""))
        return (proto, host, port, server.get("password", ""))

    return None


def existing_outbound_fingerprints(cfg: dict | None = None) -> set[tuple]:
    cfg = cfg if cfg is not None else load_config()
    fps: set[tuple] = set()
    for ob in cfg.get("outbounds", []):
        fp = outbound_fingerprint(ob)
        if fp is not None:
            fps.add(fp)
    return fps


# ─── Outbound Builder ────────────────────────────────────────────────────────

def build_outbound(proxy: dict, tag: str) -> dict:
    """Build a tagged Xray outbound config for a proxy."""
    proto = proxy["protocol"]

    if proto == "vmess":
        return {
            "tag": tag,
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": proxy["host"],
                    "port": proxy["port"],
                    "users": [{
                        "id": proxy["uuid"],
                        "alterId": proxy.get("alter_id", 0),
                        "security": proxy.get("security", "auto"),
                    }]
                }]
            },
            "streamSettings": {
                "network": proxy.get("network", "tcp"),
                "security": "tls" if proxy.get("tls") == "tls" else "none",
            },
        }

    if proto == "vless":
        stream: dict = {
            "network": proxy.get("network", "tcp"),
            "security": proxy.get("security", "none"),
        }
        if proxy.get("security") == "reality":
            stream["realitySettings"] = {
                "serverName": proxy.get("sni", ""),
                "fingerprint": proxy.get("fp", "chrome"),
                "publicKey": proxy.get("pbk", ""),
                "shortId": proxy.get("sid", ""),
            }
        elif proxy.get("security") == "tls":
            stream["tlsSettings"] = {
                "serverName": proxy.get("sni", proxy["host"]),
                "fingerprint": proxy.get("fp", ""),
            }
        return {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": proxy["host"],
                    "port": proxy["port"],
                    "users": [{
                        "id": proxy["uuid"],
                        "encryption": proxy.get("encryption", "none"),
                        "flow": proxy.get("flow", ""),
                    }]
                }]
            },
            "streamSettings": stream,
        }

    if proto == "shadowsocks":
        return {
            "tag": tag,
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": proxy["host"],
                    "port": proxy["port"],
                    "method": proxy["method"],
                    "password": proxy["password"],
                }]
            },
        }

    if proto == "trojan":
        return {
            "tag": tag,
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": proxy["host"],
                    "port": proxy["port"],
                    "password": proxy["password"],
                }]
            },
            "streamSettings": {
                "network": proxy.get("network", "tcp"),
                "security": "tls",
                "tlsSettings": {
                    "serverName": proxy.get("sni", proxy["host"]),
                    "allowInsecure": False,
                },
            },
        }

    return {}


# ─── Single-config Manager ───────────────────────────────────────────────────

def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return {k: (v.copy() if isinstance(v, (dict, list)) else v)
            for k, v in EMPTY_CONFIG.items()}


def save_config(cfg: dict) -> None:
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def get_used_ports() -> set[int]:
    cfg = load_config()
    ports: set[int] = set()
    for ib in cfg.get("inbounds", []):
        try:
            ports.add(int(ib["port"]))
        except (KeyError, ValueError):
            pass
    return ports


def next_free_port() -> int | None:
    used = get_used_ports()
    for p in range(PORT_START, PORT_END + 1):
        if p not in used:
            return p
    return None


DOCKER_SOCKET = "/var/run/docker.sock"


class _DockerConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(DOCKER_SOCKET)


def _docker_request(
    method: str,
    path: str,
    body: dict | None = None,
    *,
    json_response: bool = True,
) -> tuple[int, dict | str | bytes]:
    conn = _DockerConnection("localhost")
    payload = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if payload else {}
    try:
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        status = resp.status
    except (FileNotFoundError, ConnectionRefusedError, OSError) as exc:
        return 0, str(exc)
    finally:
        conn.close()

    if not data:
        return status, ""
    if not json_response:
        return status, data
    try:
        return status, json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return status, data.decode("utf-8", errors="replace")


def reload_xray() -> dict:
    """Send SIGHUP to the Xray process for a hot config reload (no restart)."""
    status, data = _docker_request(
        "POST",
        f"/containers/{XRAY_CONTAINER}/exec",
        {"Cmd": ["kill", "-SIGHUP", "1"]},
    )
    if status != 201 or not isinstance(data, dict):
        return {"returncode": 1, "stderr": str(data)}
    start_status, _ = _docker_request(
        "POST",
        f"/exec/{data['Id']}/start",
        {"Detach": True, "Tty": False},
        json_response=False,
    )
    return {"returncode": 0 if start_status == 204 else 1, "stderr": ""}


def add_proxy(proxy: dict, *, reload: bool = True) -> dict:
    proxy_id = proxy["id"]
    inbound_tag = f"inbound-{proxy_id}"
    outbound_tag = f"outbound-{proxy_id}"

    outbound = build_outbound(proxy, outbound_tag)
    if not outbound:
        return {"error": f"Unsupported protocol: {proxy.get('protocol')}"}

    cfg = load_config()
    fp = proxy_fingerprint(proxy)

    # Skip if same endpoint+credentials already configured (any proxy id)
    if fp in existing_outbound_fingerprints(cfg):
        return {
            "skipped": True,
            "reason": "duplicate",
            "protocol": proxy.get("protocol"),
            "host": proxy.get("host", ""),
            "port": proxy.get("port"),
        }

    # Guard against colliding generated ids
    if any(ib.get("tag") == inbound_tag for ib in cfg.get("inbounds", [])):
        return {"error": "Proxy already exists"}

    port = next_free_port()
    if port is None:
        return {"error": "No free ports available"}

    cfg["inbounds"].append({
        "tag": inbound_tag,
        "port": port,
        "listen": "0.0.0.0",
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    })

    # Insert proxy outbound before the freedom/direct fallback
    freedom_idx = next(
        (i for i, ob in enumerate(cfg["outbounds"]) if ob.get("protocol") == "freedom"),
        len(cfg["outbounds"]),
    )
    cfg["outbounds"].insert(freedom_idx, outbound)

    cfg.setdefault("routing", {"rules": []})
    cfg["routing"]["rules"].append({
        "type": "field",
        "inboundTag": [inbound_tag],
        "outboundTag": outbound_tag,
    })

    save_config(cfg)
    reload_result = reload_xray() if reload else {"returncode": 0, "stderr": ""}

    return {
        "proxy_id": proxy_id,
        "port": port,
        "protocol": proxy["protocol"],
        "host": proxy.get("host", ""),
        "returncode": reload_result["returncode"],
        "stderr": reload_result["stderr"],
    }


def remove_proxy(proxy_id: str) -> dict:
    inbound_tag = f"inbound-{proxy_id}"
    outbound_tag = f"outbound-{proxy_id}"

    cfg = load_config()
    before = len(cfg.get("inbounds", []))

    cfg["inbounds"] = [ib for ib in cfg.get("inbounds", [])
                       if ib.get("tag") != inbound_tag]
    cfg["outbounds"] = [ob for ob in cfg.get("outbounds", [])
                        if ob.get("tag") != outbound_tag]
    if "routing" in cfg:
        cfg["routing"]["rules"] = [
            r for r in cfg["routing"].get("rules", [])
            if r.get("outboundTag") != outbound_tag
        ]

    if len(cfg.get("inbounds", [])) == before:
        return {"error": "Proxy not found"}

    save_config(cfg)
    reload_xray()
    return {"success": True, "removed": proxy_id}


def get_xray_status() -> str:
    status, data = _docker_request("GET", f"/containers/{XRAY_CONTAINER}/json")
    if status == 404:
        return "not_found"
    if status != 200 or not isinstance(data, dict):
        return "unknown"
    return data.get("State", {}).get("Status", "unknown")


def list_proxies() -> list[dict]:
    cfg = load_config()
    container_status = get_xray_status()

    outbound_map = {ob.get("tag"): ob for ob in cfg.get("outbounds", [])}
    proxies = []

    for ib in cfg.get("inbounds", []):
        tag = ib.get("tag", "")
        if not tag.startswith("inbound-"):
            continue
        proxy_id = tag[len("inbound-"):]
        ob = outbound_map.get(f"outbound-{proxy_id}", {})

        protocol = ob.get("protocol", "unknown")
        remote_host = ""
        for key in ("vnext", "servers"):
            servers = ob.get("settings", {}).get(key, [])
            if servers:
                remote_host = servers[0].get("address", "")
                break

        proxies.append({
            "name": f"proxy-{proxy_id}",
            "proxy_id": proxy_id,
            "port": ib.get("port"),
            "protocol": protocol,
            "remote_host": remote_host,
            "status": container_status,
        })

    return proxies


def country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c.upper()) - ord("A")) for c in code)


def lookup_country_via_proxy(socks_port: int) -> dict:
    """Resolve exit country by querying ip-api.com through the local SOCKS inbound."""
    cached = _geo_cache.get(socks_port)
    if cached and time.time() - cached[0] < GEO_CACHE_TTL:
        return cached[1]

    proxy_url = f"socks5h://{PROXY_CONNECT_HOST}:{socks_port}"
    try:
        resp = requests.get(
            IP_API_URL,
            proxies={"http": proxy_url},
            timeout=(5, 12),
            headers={"Connection": "close"},
        )
        resp.raise_for_status()
        payload = resp.json()
    except requests.RequestException as exc:
        data = {"error": str(exc)}
        _geo_cache[socks_port] = (time.time(), data)
        return data
    except json.JSONDecodeError:
        data = {"error": "invalid response"}
        _geo_cache[socks_port] = (time.time(), data)
        return data

    if payload.get("status") != "success":
        data = {"error": payload.get("message", "lookup failed")}
        _geo_cache[socks_port] = (time.time(), data)
        return data

    code = payload.get("countryCode", "")
    data = {
        "country": payload.get("country", ""),
        "country_code": code,
        "ip": payload.get("query", ""),
        "flag": country_flag(code),
    }
    _geo_cache[socks_port] = (time.time(), data)
    return data


def lookup_all_proxy_countries(proxies: list[dict]) -> dict[str, dict]:
    geo: dict[str, dict] = {}
    if not proxies:
        return geo

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {
            pool.submit(lookup_country_via_proxy, p["port"]): p["name"]
            for p in proxies
            if p.get("port")
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                geo[name] = future.result()
            except Exception as exc:
                geo[name] = {"error": str(exc)}
    return geo


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/parse", methods=["POST"])
def api_parse():
    text = request.json.get("text", "")
    proxies = extract_proxies(text)
    return jsonify({"proxies": proxies, "count": len(proxies)})


@app.route("/api/deploy", methods=["POST"])
def api_deploy():
    proxies = request.json.get("proxies", [])
    results = [add_proxy(proxy, reload=False) for proxy in proxies]
    reload_result = reload_xray()
    for result in results:
        if "error" not in result:
            result["returncode"] = reload_result["returncode"]
            result["stderr"] = reload_result["stderr"]
    return jsonify({"results": results})


@app.route("/api/services", methods=["GET"])
def api_services():
    return jsonify({"services": list_proxies()})


@app.route("/api/services/geo", methods=["GET"])
def api_services_geo():
    proxies = list_proxies()
    return jsonify({"geo": lookup_all_proxy_countries(proxies)})


@app.route("/api/services/<proxy_name>", methods=["DELETE"])
def api_remove_service(proxy_name):
    proxy_id = proxy_name.removeprefix("proxy-")
    return jsonify(remove_proxy(proxy_id))


@app.route("/api/services/<proxy_name>/stop", methods=["POST"])
def api_stop_service(proxy_name):
    status, _ = _docker_request("POST", f"/containers/{XRAY_CONTAINER}/stop")
    return jsonify({"stdout": "", "returncode": 0 if status in (204, 304) else 1})


@app.route("/api/services/<proxy_name>/start", methods=["POST"])
def api_start_service(proxy_name):
    status, _ = _docker_request("POST", f"/containers/{XRAY_CONTAINER}/start")
    return jsonify({"stdout": "", "returncode": 0 if status == 204 else 1})


@app.route("/api/xray/reload", methods=["POST"])
def api_reload_xray():
    return jsonify(reload_xray())


@app.route("/api/xray/status", methods=["GET"])
def api_xray_status():
    return jsonify({"status": get_xray_status()})


if __name__ == "__main__":
    if not CONFIG_FILE.exists():
        save_config({k: (list(v) if isinstance(v, list) else dict(v) if isinstance(v, dict) else v)
                     for k, v in EMPTY_CONFIG.items()})
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=True)
