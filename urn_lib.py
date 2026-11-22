"""Shared library for URnetwork (BringYour) proxy draw scripts.

Credentials policy (hard rule):
- api_key / auth_token / any JWT live ONLY in credentials/state files and
  in-memory. Every print/log goes through redact(); raw values never reach
  stdout, stderr or log files.
"""
import base64
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
from urllib.parse import urlparse

API_BASE = "https://api.bringyour.com"
DEFAULT_SOCKS_HOST = "crisp.bringyour.com"
DEFAULT_SOCKS_PORT = 7117
IPAPI_URL = ("http://ip-api.com/json/?fields=status,message,country,countryCode,"
             "regionName,city,isp,org,as,proxy,hosting,query")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CRED_FILE = os.path.join(BASE_DIR, "urn_credentials.json")
STATE_FILE = os.path.join(BASE_DIR, "urn_state.json")
OUT_DIR = os.path.join(BASE_DIR, "out")
LOG_FILE = os.path.join(BASE_DIR, "urn_draw.log")

#isp/org/as substrings that mark a datacenter/hosting operator -> not a real
#residential ISP (checked lowercased against isp+org+as)
BAD_ISP_KEYWORDS = [
    "ovh", "hetzner", "digitalocean", "linode", "akamai", "vultr", "choopa",
    "contabo", "amazon", "aws ", "oracle", "alibaba", "tencent", "huawei",
    "microsoft", "azure", "google cloud", "google llc", "gcore", "m247",
    "datacamp", "packethub", "psychz", "quadranet", "colocation", "colocationusa",
    "data center", "datacenter", "hosting", "hostwinds", "hostinger", "cloudflare",
    "leaseweb", ".server ", "servers", "vps", "colo", "incognet", "path.net",
    "buyvm", "frantech", "ramnode", "bandwagon", "moonshot", "cogent",
]

_SECRETS = set()          # raw secret strings to redact everywhere
_LOG_FH = None


# ---------------------------------------------------------------- logging

def _logfh():
    global _LOG_FH
    if _LOG_FH is None:
        _LOG_FH = open(LOG_FILE, "a", encoding="utf8")
    return _LOG_FH


def register_secret(value):
    """Remember a raw secret so redact() scrubs it from all output."""
    if value and isinstance(value, str) and len(value) >= 8:
        _SECRETS.add(value)


def redact(text):
    s = str(text)
    for sec in sorted(_SECRETS, key=len, reverse=True):
        if sec in s:
            s = s.replace(sec, "<REDACTED>")
    return s


def out(*args):
    """Print (and log) only through here - always redacted."""
    line = " ".join(str(a) for a in args)
    line = redact(line)
    print(line, flush=True)
    try:
        fh = _logfh()
        fh.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + line + "\n")
        fh.flush()
    except Exception:
        pass


def sanitize_json(obj):
    """Return a copy of obj safe for printing: secret-valued keys masked,
    and any unknown long token strings registered + masked."""
    secret_keys = {"auth_token", "api_key", "by_jwt", "by_client_jwt",
                   "jwt", "password", "client_jwt", "token"}

    def scrub(v, key=None):
        if isinstance(v, dict):
            return {k: scrub(x, k) for k, x in v.items()}
        if isinstance(v, list):
            return [scrub(x) for x in v]
        if key in secret_keys and isinstance(v, str) and v:
            register_secret(v)
            return "<REDACTED>"
        return v

    return scrub(obj)


# ---------------------------------------------------------------- files

def _chmod600(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # best effort on Windows


def load_json_file(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf8") as fh:
        return json.load(fh)


def save_json_file(path, data):
    with open(path, "w", encoding="utf8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    _chmod600(path)


def load_api_key():
    """api_key from env URN_API_KEY or urn_credentials.json. Never printed."""
    key = os.environ.get("URN_API_KEY", "").strip()
    if key:
        register_secret(key)
        return key
    cred = load_json_file(CRED_FILE)
    key = (cred.get("api_key") or "").strip()
    if key:
        register_secret(key)
    return key


def load_state():
    return load_json_file(STATE_FILE)


def save_state(state):
    save_json_file(STATE_FILE, state)


# ---------------------------------------------------------------- API

def api_call(method, path, body=None, token=None, timeout=40):
    """POST/GET to api.bringyour.com. Returns parsed JSON (or {'_raw': text}).
    HTTP or embedded 'error' failures are returned, never raised, so the
    caller decides per SOP (stop on rate limits, continue otherwise)."""
    import requests  # local import so dry-run works without network deps

    url = API_BASE + path
    headers = {"Content-Type": "application/json", "User-Agent": "urn-draw/1.0"}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        if method == "GET":
            resp = requests.get(url, headers=headers, timeout=timeout)
        else:
            resp = requests.post(url, headers=headers,
                                 data=json.dumps(body or {}), timeout=timeout)
    except Exception as exc:
        return {"_http_error": redact(str(exc))}

    text = resp.text
    try:
        data = json.loads(text)
    except ValueError:
        data = {"_raw": text, "_status": resp.status_code}
    if isinstance(data, dict):
        data.setdefault("_status", resp.status_code)
    return data


def api_error(data):
    """Extract the embedded error object (200-with-error refusals included)."""
    if not isinstance(data, dict):
        return None
    err = data.get("error")
    if isinstance(err, dict) and err.get("message"):
        return err
    return None


# ---------------------------------------------------------------- curl / probes

def curl_socks(socks_host, socks_port, username, password, url,
               timeout=30, preproxy=None, extra=None):
    """GET url through a SOCKS5 proxy via curl. Returns (rc, stdout)."""
    cmd = ["curl", "-s", "--connect-timeout", "12",
           "--max-time", str(timeout),
           "--socks5-hostname", "%s:%s" % (socks_host, socks_port),
           "--proxy-user", "%s:%s" % (username, password)]
    if preproxy:
        cmd += ["--preproxy", preproxy]
    if extra:
        cmd += extra
    cmd += [url]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf8", errors="replace", timeout=timeout + 10)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return 28, "curl timeout"
    except FileNotFoundError:
        return 127, "curl not found"


def http_get_via_httpproxy(host, http_port, user, password, url,
                           preproxy=None, timeout=30, max_bytes=None,
                           max_seconds=None):
    """HTTP GET through a plain HTTP proxy (CONNECT for https targets,
    absolute-URL GET for http targets). Same return shape as
    http_via_socks."""
    parsed = urlparse(url)
    target_host = parsed.hostname
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    def _proxy_socket():
        if preproxy:
            m = re.match(r"socks5h?://([^:/]+):(\d+)", preproxy)
            if not m:
                raise ValueError("bad preproxy url")
            pre = socks5_chain(m.group(1), int(m.group(2)), None, None,
                               None, timeout)
            # tunnel TCP to the http proxy through the socks preproxy
            _socks_connect(pre, host, int(http_port))
            return pre
        return socket.create_connection((host, int(http_port)),
                                        timeout=timeout)

    auth = base64.b64encode(("%s:x" % user).encode()).decode()
    try:
        sock = _proxy_socket()
        sock.settimeout(timeout)
        if parsed.scheme == "https":
            req = ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
                   "Proxy-Authorization: Basic %s\r\n\r\n"
                   % (target_host, target_port, target_host, target_port,
                      auth)).encode()
            sock.sendall(req)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ConnectionError("proxy closed during CONNECT")
                buf += chunk
            status_line = buf.split(b"\r\n", 1)[0].decode("latin1")
            if " 200" not in status_line:
                raise ConnectionError("CONNECT refused: %s" % status_line[:60])
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=target_host)
            send_req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: "
                        "Mozilla/5.0 Chrome/126.0\r\nAccept: */*\r\n"
                        "Connection: close\r\n\r\n" % (path, target_host))
            sock.sendall(send_req.encode())
        else:
            req = ("GET %s://%s:%d%s HTTP/1.1\r\nHost: %s\r\n"
                   "Proxy-Authorization: Basic %s\r\n"
                   "User-Agent: Mozilla/5.0 Chrome/126.0\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n"
                   % (parsed.scheme, target_host, target_port, path,
                      target_host, auth)).encode()
            sock.sendall(req)

        deadline = time.time() + (max_seconds or timeout)
        raw = b""
        status, headers, body = None, {}, b""
        while True:
            if max_bytes is not None and len(body) >= max_bytes:
                break
            if max_seconds is not None and time.time() > deadline:
                break
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            raw += chunk
            if status is None:
                head_end = raw.find(b"\r\n\r\n")
                if head_end >= 0:
                    head = raw[:head_end].decode("latin1", "replace")
                    first = head.split("\r\n", 1)[0]
                    m = re.match(r"HTTP/1\.[01] (\d{3})", first)
                    status = int(m.group(1)) if m else None
                    for line in head.split("\r\n")[1:]:
                        if ":" in line:
                            k, v = line.split(":", 1)
                            headers[k.strip().lower()] = v.strip()
                    body = raw[head_end + 4:]
            else:
                body += chunk
        try:
            sock.close()
        except OSError:
            pass
        return status, headers, body
    except Exception as exc:
        return None, {}, "%s: %s" % (type(exc).__name__, redact(str(exc))[:160])


def ipapi_via_httpproxy(proxy, preproxy=None):
    """Exit-IP query through the plain HTTP proxy fallback path
    (http_proxy_url / http_proxy_port), via curl. Returns dict or None."""
    cmd = ["curl", "-s", "--max-time", "35",
           "-x", "http://%s:x@%s:%s" % (proxy["user"], proxy["host"],
                                        proxy.get("http_port")),
           IPAPI_URL]
    if preproxy:
        cmd = ["curl", "-s", "--max-time", "40",
               "--preproxy", preproxy,
               "-x", "http://%s:x@%s:%s" % (proxy["user"], proxy["host"],
                                            proxy.get("http_port")),
               IPAPI_URL]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf8", errors="replace", timeout=45)
        text = (proc.stdout or "").strip()
        if proc.returncode != 0 or not text:
            out("http-proxy probe failed: rc=%d %s" % (
                proc.returncode, redact((proc.stderr or "")[-120:])))
            return None
        return json.loads(text.splitlines()[-1])
    except Exception as exc:
        out("http-proxy probe error:", redact(str(exc))[:120])
        return None


def ipapi_via_socks(proxy, preproxy=None):
    """Exit-IP query through the proxy. Returns dict or None (errors are
    logged, redacted)."""
    status, headers, body = http_via_socks(proxy["host"], proxy["port"],
                                           proxy["user"], proxy["pass"],
                                           IPAPI_URL, preproxy=preproxy,
                                           timeout=30)
    if isinstance(body, str):  # error string from the exception path
        out("gateway probe failed via %s: %s:%s -> %s" % (
            "preproxy" if preproxy else "direct", proxy["host"],
            proxy["port"], body))
        return None
    if not body:
        return None
    try:
        return json.loads(body.decode("utf8", "replace").strip())
    except ValueError:
        return None


# ------------------------------------------------- pure-python socks5 chain
# curl --preproxy + --socks5-hostname silently drops the second hop for
# socks-over-socks, so exit tests use this explicit chain instead:
#   client -> [preproxy socks5] -> gateway socks5 (token auth) -> target

def _socks_read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socks stream closed")
        buf += chunk
    return buf


def _socks_handshake(sock, user, password):
    # RFC 1928: VER NMETHODS METHODS...  (two methods when we have creds)
    if user:
        sock.sendall(b"\x05\x02\x00\x02")
    else:
        sock.sendall(b"\x05\x01\x00")
    resp = _socks_read_exact(sock, 2)
    if resp[0] != 5:
        raise ConnectionError("not socks5 (got %r)" % resp)
    if resp[1] == 0x00:
        return
    if resp[1] == 0x02:
        u = (user or "").encode()
        p = (password or "").encode()
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        r2 = _socks_read_exact(sock, 2)
        if r2[1] != 0x00:
            raise ConnectionError("socks auth refused (code %d)" % r2[1])
        return
    raise ConnectionError("no acceptable socks auth method (0x%02x)" % resp[1])


def _socks_connect(sock, host, port):
    hb = host.encode()
    req = b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + \
        struct.pack(">H", port)
    sock.sendall(req)
    head = _socks_read_exact(sock, 4)
    if head[1] != 0x00:
        raise ConnectionError("socks connect refused (code %d)" % head[1])
    atyp = head[3]
    if atyp == 1:
        _socks_read_exact(sock, 4 + 2)
    elif atyp == 3:
        n = _socks_read_exact(sock, 1)[0]
        _socks_read_exact(sock, n + 2)
    elif atyp == 4:
        _socks_read_exact(sock, 16 + 2)


_DNS_CACHE = {}


def resolve_host(host):
    """Resolve host to IPs: system DNS first (skipping 198.18.0.0/16
    fake-IPs from TUN), then public DoH (dns.google, cloudflare) as
    cross-checked fallback. Returns list of IPs."""
    if host in _DNS_CACHE:
        return _DNS_CACHE[host]
    ips = []
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips = sorted({i[4][0] for i in infos
                      if not i[4][0].startswith("198.18.")})
    except OSError:
        pass
    if not ips:
        for url in ("https://dns.google/resolve?name=%s&type=A",
                    "https://cloudflare-dns.com/dns-query?name=%s&type=A"):
            try:
                import requests as _rq
                r = _rq.get(url % host, headers={"accept": "application/dns-json"},
                            timeout=10)
                answers = [a["data"] for a in r.json().get("Answer", [])
                           if a.get("type") == 1]
                if answers:
                    ips = sorted(set(answers))
                    break
            except Exception:
                continue
    if ips:
        _DNS_CACHE[host] = ips
    return ips


def socks5_chain(host, port, user, password, preproxy=None, timeout=20):
    """Open a socket tunneled to host:port through an optional socks5
    preproxy, authenticating to the gateway with user/password.
    Domain names are resolved via resolve_host() and dialed by IP."""
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        host_ip = host
    else:
        ips = resolve_host(host)
        if not ips:
            raise ConnectionError("cannot resolve %s" % host)
        host_ip = ips[0]
    p_host, p_port = None, None
    if preproxy:
        m = re.match(r"socks5h?://([^:/]+):(\d+)", preproxy)
        if not m:
            raise ValueError("bad preproxy url: %r" % preproxy)
        p_host, p_port = m.group(1), int(m.group(2))
    sock = socket.create_connection(
        (p_host or host_ip, p_port or port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        if preproxy:
            _socks_handshake(sock, None, None)
            _socks_connect(sock, host_ip, port)
        _socks_handshake(sock, user, password)
        _socks_connect(sock, host_ip, port)
        return sock
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise


def http_via_socks(host, port, user, password, url, preproxy=None,
                   timeout=30, max_bytes=None, max_seconds=None):
    """GET a URL through the socks5 chain. Returns (status, headers_dict,
    body_bytes) or (None, {}, error_string). With max_seconds/max_bytes:
    stream-capped read for speed tests."""
    parsed = urlparse(url)
    target_host = parsed.hostname
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        sock = socks5_chain(host, port, user, password, preproxy, timeout)
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=target_host)
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 "
               "(Windows NT 10.0; Win64; x64) Chrome/126.0\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n"
               % (path, target_host)).encode()
        sock.sendall(req)

        deadline = time.time() + (max_seconds or timeout)
        raw = b""
        status, headers, body = None, {}, b""
        while True:
            if max_bytes is not None and len(body) >= max_bytes:
                break
            if max_seconds is not None and time.time() > deadline:
                break
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            raw += chunk
            if status is None:
                head_end = raw.find(b"\r\n\r\n")
                if head_end >= 0:
                    head = raw[:head_end].decode("latin1", "replace")
                    first = head.split("\r\n", 1)[0]
                    m = re.match(r"HTTP/1\.[01] (\d{3})", first)
                    status = int(m.group(1)) if m else None
                    for line in head.split("\r\n")[1:]:
                        if ":" in line:
                            k, v = line.split(":", 1)
                            headers[k.strip().lower()] = v.strip()
                    body = raw[head_end + 4:]
            else:
                body += chunk
        try:
            sock.close()
        except OSError:
            pass
        return status, headers, body
    except Exception as exc:
        return None, {}, "%s: %s" % (type(exc).__name__, redact(str(exc))[:160])


def judge_exit(info, country_code):
    """SOP judgement: proxy=false & hosting=false, real broadband ISP,
    geo self-consistent. Returns (ok, reasons[list of str])."""
    if not info:
        return False, ["no exit info (gateway unreachable?)"]
    reasons = []
    if info.get("status") != "success":
        return False, ["ip-api status=%s" % info.get("status")]
    if info.get("proxy") is not False:
        reasons.append("proxy=%s" % info.get("proxy"))
    if info.get("hosting") is not False:
        reasons.append("hosting=%s" % info.get("hosting"))
    cc = (info.get("countryCode") or "").lower()
    if country_code and cc != country_code.lower():
        reasons.append("country=%s" % info.get("country"))
    city = (info.get("city") or "").strip()
    isp = "%s %s %s" % (info.get("isp") or "", info.get("org") or "",
                        info.get("as") or "")
    isp_l = isp.lower()
    if not city or city.lower() == (info.get("country") or "").lower():
        reasons.append("city missing/vague: %r" % city)
    hit = [kw for kw in BAD_ISP_KEYWORDS if kw in isp_l]
    if hit:
        reasons.append("datacenter-like ISP keyword: %s" % hit)
    return (not reasons), reasons


# ---------------------------------------------------------------- deliverables

def sanitize_frag(text):
    """Fragment for the v2rayN node name: drop characters that break URIs."""
    for ch in "#@/\\\t\n\r:?[]":
        text = text.replace(ch, "")
    return text.strip().replace(" ", "-") or "Unknown"


def write_deliverables(proxy, exit_info, speed_mbps, codes, path="socks"):
    """Write the v2rayN plaintext link .txt + optional Xray config, matching
    the VERIFIED data path (socks or http - the platform's socks path dies
    for some providers while http_proxy_port keeps working).
    Secrets are written into these FILES only (allowed: config use)."""
    os.makedirs(OUT_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    city = sanitize_frag(exit_info.get("city") or "City")
    isp = sanitize_frag((exit_info.get("isp") or "ISP").split(",")[0])
    name = "URnetwork-US-%s-%s-Clean-" % (city, isp)

    if path.startswith("http"):
        host, port = proxy["host"], proxy["http_port"]
        scheme = "http" if path == "http" else "https"
        link = "%s://%s:@%s:%s#%s" % (scheme, proxy["user"], host, port, name)
    else:
        host, port = proxy["host"], proxy["port"]
        link = "socks://%s:@%s:%s#%s" % (proxy["user"], host, port, name)
    txt_path = os.path.join(OUT_DIR, "URnetwork-US-%s-%s-Clean.txt" % (city, isp))
    with open(txt_path, "w", encoding="utf8", newline="\n") as fh:
        fh.write(link + "\n")
    _chmod600(txt_path)

    if path.startswith("http"):
        outbound = {
            "tag": "proxy", "protocol": "http",
            "settings": {"servers": [{
                "address": host, "port": int(port),
                "users": [{"user": proxy["user"], "pass": ""}]
            }]}
        }
    else:
        outbound = {
            "tag": "proxy", "protocol": "socks",
            "settings": {"servers": [{
                "address": host, "port": int(port),
                "users": [{"user": proxy["user"], "pass": ""}]
            }]}
        }
    xray = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in", "listen": "127.0.0.1", "port": 10810,
            "protocol": "socks", "settings": {"udp": True, "auth": "noauth"}
        }],
        "outbounds": [outbound, {"tag": "direct", "protocol": "freedom",
                                 "settings": {}}],
        "routing": {"rules": [{
            "type": "field", "ip": ["geoip:private"], "outboundTag": "direct"
        }]}
    }
    xray_path = os.path.join(OUT_DIR, "xray_config_%s.json" % ts)
    with open(xray_path, "w", encoding="utf8", newline="\n") as fh:
        json.dump(xray, fh, indent=2, ensure_ascii=False)

    return txt_path, xray_path, name
