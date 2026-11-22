"""Turn the draw result into GitHub Pages artifacts.

Reads urn_state.json (written by urn_draw.py on success) and produces a
site/ directory ready to be pushed to the gh-pages branch:

  site/
    index.html            status page - NO secrets
    status.json           machine metadata - NO secrets
    node-<rand>/node.txt  the plaintext v2rayN socks:// link  (contains token)
    node-<rand>/sub-singbox.json   sing-box subscription         (contains token)

The random path segment makes the token-bearing files unguessable; every
redraw rotates the path together with the token (old proxy is removed, old
URL dies).

edgetunnel chaining (option A in CHAINING.md): put the VLESS entry params in
gha/edgetunnel.json - {"server","server_port","uuid","sni","ws_path"} - and
the sing-box subscription gains a chained "us-residential" outbound with
"detour": "edgetunnel". Without that file, the subscription is socks-only
(direct to the gateway; usable where the gateway is reachable).
"""
import json
import os
import secrets as pysecrets
import time
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # urnetwork/
STATE = os.path.join(BASE, "urn_state.json")
OUT = os.path.join(BASE, "out")
SITE = os.path.join(BASE, "site")
EDGE_CFG = os.path.join(BASE, "gha", "edgetunnel.json")


def build_subscription(proxy, edge):
    socks_out = {
        "tag": "us-residential",
        "type": "socks",
        "server": proxy["host"],
        "server_port": int(proxy["port"]),
        "username": proxy["auth_token"],
        "password": "",
        "detour": "edgetunnel" if edge else None,
    }
    outbounds = []
    if edge:
        outbounds.append({
            "tag": "edgetunnel",
            "type": "vless",
            "server": edge["server"],
            "server_port": int(edge.get("server_port", 443)),
            "uuid": edge["uuid"],
            "tls": {"enabled": True, "server_name": edge.get("sni",
                    edge["server"])},
            "transport": {"type": "ws", "path": edge.get("ws_path", "/")},
        })
    socks_out = {k: v for k, v in socks_out.items() if v is not None}
    outbounds.append(socks_out)
    sub = {
        "outbounds": outbounds + [{"tag": "direct", "type": "direct"}],
        "route": {"final": "us-residential"},
    }
    return sub


def main():
    state = json.load(open(STATE, encoding="utf8"))
    last = state.get("last_success")
    if not last:
        raise SystemExit("no last_success in urn_state.json - nothing to publish")

    edge = None
    if os.path.exists(EDGE_CFG):
        try:
            edge = json.load(open(EDGE_CFG, encoding="utf8"))
            if not edge.get("uuid"):
                edge = None
        except ValueError:
            edge = None

    os.makedirs(SITE, exist_ok=True)
    rand = pysecrets.token_hex(4)
    node_dir = os.path.join(SITE, "node-%s" % rand)
    os.makedirs(node_dir, exist_ok=True)

    exit_info = last.get("exit") or {}
    drawn_at = last.get("drawn_at", "")
    ts_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    # status / index - redacted (no token)
    status = {
        "drawn_at": drawn_at,
        "published_at": ts_iso,
        "exit_ip": exit_info.get("query"),
        "city": exit_info.get("city"),
        "region": exit_info.get("regionName"),
        "country": exit_info.get("country"),
        "isp": exit_info.get("isp"),
        "org": exit_info.get("org"),
        "as": exit_info.get("as"),
        "ipapi_proxy": exit_info.get("proxy"),
        "ipapi_hosting": exit_info.get("hosting"),
        "gateway_host": last.get("host"),
        "gateway_port": last.get("port"),
        "provider_client_id": last.get("provider_client_id"),
        "checks": last.get("details") or {},
        "chained": bool(edge),
    }
    with open(os.path.join(SITE, "status.json"), "w", encoding="utf8") as fh:
        json.dump(status, fh, indent=2, ensure_ascii=False)

    index = """<!doctype html><html><head><meta charset="utf-8">
<title>URnetwork US residential node</title>
<style>body{{font-family:ui-monospace,monospace;max-width:640px;margin:40px auto;
color:#ddd;background:#141414}} td{{padding:2px 12px;color:#aaa}}</style></head>
<body><h2>URnetwork US residential node</h2>
<p>published {published_at} | drawn {drawn_at}</p>
<table>
<tr><td>exit IP</td><td><b>{ip}</b></td></tr>
<tr><td>location</td><td>{city}, {region}, {country}</td></tr>
<tr><td>ISP</td><td>{isp}</td></tr>
<tr><td>AS</td><td>{asn}</td></tr>
<tr><td>ip-api proxy/hosting</td><td>{proxy} / {hosting} (double-false required)</td></tr>
<tr><td>gateway</td><td>{gw}:{gwport}</td></tr>
<tr><td>checks</td><td>{checks}</td></tr>
<tr><td>edgetunnel chain</td><td>{chained}</td></tr>
</table>
<p>subscription: <code>./node-{rand}/sub-singbox.json</code></p>
<p>v2rayN link: <code>./node-{rand}/node.txt</code></p>
<p><i>tokens rotate on every redraw; old URLs die with their proxies.</i></p>
</body></html>""".format(
        published_at=ts_iso, drawn_at=drawn_at,
        ip=exit_info.get("query"), city=exit_info.get("city"),
        region=exit_info.get("regionName"), country=exit_info.get("country"),
        isp=exit_info.get("isp"), asn=exit_info.get("as"),
        proxy=exit_info.get("proxy"), hosting=exit_info.get("hosting"),
        gw=last.get("host"), gwport=last.get("port"),
        checks=json.dumps(last.get("details") or {}),
        chained=bool(edge), rand=rand)
    with open(os.path.join(SITE, "index.html"), "w", encoding="utf8") as fh:
        fh.write(index)

    # token-bearing deliverables
    link = "socks://%s:@%s:%s#URnetwork-US-%s-%s-Clean-" % (
        last["auth_token"], last["host"], last["port"],
        (exit_info.get("city") or "City").replace(" ", "-"),
        ((exit_info.get("isp") or "ISP").split(",")[0]).replace(" ", "-"))
    with open(os.path.join(node_dir, "node.txt"), "w", encoding="utf8",
              newline="\n") as fh:
        fh.write(link + "\n")

    sub = build_subscription(last, edge)
    with open(os.path.join(node_dir, "sub-singbox.json"), "w",
              encoding="utf8", newline="\n") as fh:
        json.dump(sub, fh, indent=2, ensure_ascii=False)

    print("published:", SITE)
    print("status:", ts_iso, exit_info.get("query"), exit_info.get("city"),
          exit_info.get("isp"))
    print("node path: node-%s" % rand, "| chained:", bool(edge))


if __name__ == "__main__":
    main()
