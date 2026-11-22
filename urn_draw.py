"""URnetwork single-provider residential proxy draw script.

Flow (per SOP):
1. resolve target country location_id (POST /network/find-provider-locations)
2. pull providers (POST /network/find-providers2, specs=[{location_id}]),
   sort by estimated_bytes_per_second desc
3. for each candidate (max N per round): POST /network/auth-client pinning
   that provider -> test exit via SOCKS5 -> double-false + ISP + geo + IP
   stability judgement -> stability tests (generate_204, x.com, speed)
4. keep the first pass; remove-client everything else

Free tier: 5 active proxies / 5 creates per minute. Refusals arrive as
200 + error.client_limit_exceeded -> per SOP we stop and report.

Usage:
  py urn_draw.py --dry-run            # no credentials needed: list candidates
  py urn_draw.py                      # draw (needs api_key)
  py urn_draw.py --tries 5 --country us
  py urn_draw.py --clean              # first remove every active proxy
  py urn_draw.py --check              # re-verify the kept node from state
  py urn_draw.py --preproxy socks5h://127.0.0.1:10808
                                      # chain all gateway tests via local proxy
"""
import argparse
import json
import sys
import time

import urn_lib as L

FREE_ACTIVE_CAP = 5
LOCAL_PREPROXY = "socks5h://127.0.0.1:10808"  # local xray, verified live


def resolve_location_id(country_code, state):
    cached = state.get("location_id_%s" % country_code)
    if cached:
        return cached, True
    data = L.api_call("POST", "/network/find-provider-locations", {})
    if data.get("_http_error"):
        return None, False
    for loc in data.get("locations", []):
        if (loc.get("country_code") or "").lower() == country_code.lower():
            return loc.get("location_id"), False
    return None, False


def _vagueness(p):
    """0 = real city claim, 1 = real region only, 2 = fully vague.
    Vague-location providers failed geo judging 10/10 across two rounds,
    so they are tried after the honest ones (speed desc within each rank)."""
    loc = p.get("location") or {}
    country = (loc.get("country") or "").strip().lower()
    city = (loc.get("city") or "").strip().lower()
    region = (loc.get("region") or "").strip().lower()
    if city and city != country:
        return 0
    if region and region != country:
        return 1
    return 2


def fetch_providers(location_id, exclude=None, count=50):
    body = {
        "specs": [{"location_id": location_id}],
        "count": count,
        "exclude_client_ids": exclude or [],
    }
    data = L.api_call("POST", "/network/find-providers2", body)
    providers = data.get("providers") or []
    providers.sort(key=lambda p: (p.get("estimated_bytes_per_second") or 0),
                   reverse=True)
    providers.sort(key=_vagueness)  # stable: keeps speed order in each rank
    return providers, data


def create_proxy(api_key, provider_client_id):
    body = {"proxy_config": {"initial_device_state": {"location": {
        "connect_location_id": {"client_id": provider_client_id}}}}}
    data = L.api_call("POST", "/network/auth-client", body, token=api_key)
    return data


def extract_proxy_info(data, provider):
    """Normalize auth-client result into our proxy dict (secrets kept local)."""
    err = L.api_error(data)
    if err:
        return None, err
    result = data.get("proxy_config_result") or {}
    client_id = data.get("client_id") or result.get("client_id")
    auth_token = result.get("auth_token") or data.get("auth_token")
    if not auth_token or not client_id:
        return None, {"message": "auth-client returned no auth_token/client_id",
                      "_keys": sorted(data.keys())}
    L.register_secret(auth_token)
    if data.get("by_client_jwt"):
        L.register_secret(data["by_client_jwt"])

    socks_url = (result.get("socks_proxy_url") or "").strip()
    host, port, user, password = None, None, None, ""
    if socks_url:
        # observed form: socks5h://host:port (token is NOT embedded)
        import re as _re
        m = _re.match(r"socks5h?://([^:@]+)(?::([^@]*))?@([^:/]+):(\d+)", socks_url)
        if m:
            user, password, host, port = m.group(1), m.group(2) or "", m.group(3), int(m.group(4))
        else:
            host, port = None, None
    if not host:
        host = (result.get("proxy_host") or L.DEFAULT_SOCKS_HOST)
        port = int(result.get("socks_proxy_port") or L.DEFAULT_SOCKS_PORT)
        user, password = auth_token, "x"
    http_port = result.get("http_proxy_port")
    return {
        "client_id": client_id,
        "provider_client_id": provider.get("client_id"),
        "provider_speed": provider.get("estimated_bytes_per_second"),
        "provider_location": provider.get("location"),
        "auth_token": auth_token,
        "socks_url": socks_url,
        "host": host, "port": port, "user": user, "pass": password,
        "http_port": int(http_port) if http_port else None,
    }, None


def remove_proxy(api_key, client_id):
    return L.api_call("POST", "/network/remove-client",
                      {"client_id": client_id}, token=api_key)


def list_proxies(api_key):
    data = L.api_call("GET", "/network/proxies", token=api_key)
    clients = data.get("clients") if isinstance(data, dict) else None
    if clients is None and isinstance(data, list):
        clients = data
    return clients or [], data


def speed_test(proxy, preproxy):
    """Stream ~15s from Cloudflare through the chain; returns (status,
    bytes, MB/s)."""
    url = "https://speed.cloudflare.com/__down?bytes=50000000"
    t0 = time.time()
    status, headers, body = L.http_via_socks(proxy["host"], proxy["port"],
                                             proxy["user"], proxy["pass"],
                                             url, preproxy=preproxy,
                                             max_seconds=15)
    elapsed = max(time.time() - t0, 0.001)
    size = len(body) if isinstance(body, bytes) else 0
    if status and size:
        return status, size, size / elapsed / 1e6
    return status, size, 0.0


def verify_candidate(proxy, country_code, preproxy, log):
    """Exit check + double query. SOCKS first; on a dead SOCKS path fall
    back to the platform's HTTP proxy (http_proxy_port) per SOP.
    Returns (ok, exit_info, reasons, path_used)."""
    time.sleep(3)  # SOP: let the proxy take effect
    info1 = L.ipapi_via_socks(proxy, preproxy)
    path = "socks" if not preproxy else "socks+preproxy"
    if not info1:
        # local network flaps (v2rayN node switching) - one patient retry
        log("gateway probe empty - retrying once in 8s")
        time.sleep(8)
        info1 = L.ipapi_via_socks(proxy, preproxy)
    if not info1 and proxy.get("http_port"):
        log("socks path dead - trying platform HTTP proxy :%s" %
            proxy["http_port"])
        info1 = L.ipapi_via_httpproxy(proxy, preproxy)
        path = "http" if not preproxy else "http+preproxy"
    ok1, reasons = L.judge_exit(info1, country_code)
    if not ok1:
        return False, info1, reasons, path
    log("exit1 ok via %s: %s %s/%s isp=%s proxy=%s hosting=%s" % (
        path, info1.get("query"), info1.get("city"),
        info1.get("regionName"), info1.get("isp"), info1.get("proxy"),
        info1.get("hosting")))
    time.sleep(6)
    info2 = (L.ipapi_via_socks(proxy, preproxy) if path.startswith("socks")
             else L.ipapi_via_httpproxy(proxy, preproxy))
    if not info2:
        return False, info1, ["second exit query failed"], path
    if info2.get("query") != info1.get("query"):
        return False, info1, ["exit IP changed: %s -> %s" % (
            info1.get("query"), info2.get("query"))], path
    ok2, reasons2 = L.judge_exit(info2, country_code)
    if not ok2:
        return False, info2, reasons2, path
    return True, info2, [], path


def _fetch(proxy, path, url, preproxy, timeout=30, max_bytes=None,
           max_seconds=None):
    """Dispatch an HTTP GET through the path chosen at verify time."""
    pre = preproxy if path.endswith("preproxy") else None
    if path.startswith("socks"):
        return L.http_via_socks(proxy["host"], proxy["port"], proxy["user"],
                                proxy["pass"], url, preproxy=pre,
                                timeout=timeout, max_bytes=max_bytes,
                                max_seconds=max_seconds)
    return L.http_get_via_httpproxy(proxy["host"], proxy["http_port"],
                                    proxy["user"], proxy["pass"], url,
                                    preproxy=pre, timeout=timeout,
                                    max_bytes=max_bytes,
                                    max_seconds=max_seconds)


def speed_test(proxy, path, preproxy):
    """Stream ~15s from Cloudflare through the chain; returns (status,
    bytes, MB/s)."""
    url = "https://speed.cloudflare.com/__down?bytes=50000000"
    t0 = time.time()
    status, headers, body = _fetch(proxy, path, url, preproxy,
                                   max_seconds=15)
    elapsed = max(time.time() - t0, 0.001)
    size = len(body) if isinstance(body, bytes) else 0
    if status and size:
        return status, size, size / elapsed / 1e6
    return status, size, 0.0


def stability_tests(proxy, path, preproxy, log):
    """generate_204 -> 204, x.com -> 200 (redirects followed), speed.
    Returns (ok, details dict)."""
    details = {}
    status, headers, body = _fetch(proxy, path,
                                   "https://www.google.com/generate_204",
                                   preproxy, timeout=25)
    details["generate_204"] = status
    if status != 204:
        return False, details
    url = "https://x.com/"
    status = None
    for _ in range(4):
        status, headers, body = _fetch(proxy, path, url, preproxy,
                                       timeout=30, max_bytes=200000)
        if status in (301, 302, 307, 308) and headers.get("location"):
            url = headers["location"]
            continue
        break
    details["x.com"] = status
    if status != 200:
        return False, details
    code, size, mbps = speed_test(proxy, path, preproxy)
    details["speed"] = {"code": code, "bytes": size,
                        "mbps": round(mbps * 8, 2)}  # Mbps
    log("speed: %s bytes in 15s cap -> %.2f Mbps" % (size, mbps * 8))
    return True, details


def draw(args):
    state = L.load_state()
    country = args.country.lower()

    location_id, cached = resolve_location_id(country, state)
    if not location_id:
        L.out("ERROR: cannot resolve location_id for", country)
        return 1
    L.out("location_id(%s) = %s%s" % (country, location_id,
                                      " (cached)" if cached else " (fresh)"))
    state["location_id_%s" % country] = location_id
    L.save_state(state)

    tried = state.setdefault("tried_provider_client_ids", [])
    providers, raw = fetch_providers(location_id, exclude=tried,
                                     count=args.count)
    if not providers:
        L.out("ERROR: no providers returned for", country)
        L.out("raw:", json.dumps(L.sanitize_json(raw), ensure_ascii=False)[:400])
        return 1
    L.out("providers: %d (after excluding %d tried)" % (len(providers), len(tried)))
    for i, p in enumerate(providers[:12]):
        loc = p.get("location") or {}
        L.out("  #%d %s  %8.2f MB/s  tier=%s  %s / %s" % (
            i + 1, p.get("client_id"),
            (p.get("estimated_bytes_per_second") or 0) / 1e6,
            p.get("tier"), loc.get("region"), loc.get("city")))
    if args.dry_run:
        L.out("dry-run: stopping before auth-client (no credentials used)")
        return 0

    api_key = L.load_api_key()
    if not api_key:
        L.out("ERROR: no api_key. Put it in", L.CRED_FILE,
              'as {"api_key": "urn_..."} or set URN_API_KEY env.')
        return 1

    # active proxy inventory; SOP cap: 5
    proxies, praw = list_proxies(api_key)
    active = [c for c in proxies if not c.get("removed")]
    L.out("active proxies on network: %d" % len(active))
    if args.clean and active:
        for c in active:
            cid = c.get("client_id")
            L.out("removing existing proxy", cid)
            remove_proxy(api_key, cid)
            time.sleep(1)
        proxies, _ = list_proxies(api_key)
        active = [c for c in proxies if not c.get("removed")]
        L.out("after clean, active: %d" % len(active))
    if len(active) >= FREE_ACTIVE_CAP:
        L.out("ERROR: %d active proxies >= free cap %d; "
              "remove some first (rerun with --clean)." % (len(active), FREE_ACTIVE_CAP))
        return 1

    tries = 0
    for p in providers:
        if tries >= args.tries:
            break
        tries += 1
        pcid = p.get("client_id")
        loc = p.get("location") or {}
        L.out("--- try %d/%d provider=%s speed=%.2fMB/s loc=%s/%s" % (
            tries, args.tries, pcid,
            (p.get("estimated_bytes_per_second") or 0) / 1e6,
            loc.get("region"), loc.get("city")))

        data = create_proxy(api_key, pcid)
        proxy, err = extract_proxy_info(data, p)
        if not proxy:
            L.out("auth-client refused:", json.dumps(
                L.sanitize_json(err or data), ensure_ascii=False)[:300])
            msg = (err or {}).get("message", "") or ""
            if "minute" in msg or "limit" in msg.lower():
                L.out("STOP: platform limit reached (SOP: no blind retries).")
                return 1
            tried.append(pcid)
            L.save_state(state)
            continue

        L.out("proxy created client_id=%s host=%s port=%s (socks_url %s)" % (
            proxy["client_id"], proxy["host"], proxy["port"],
            "present" if proxy["socks_url"] else "EMPTY -> crisp gateway"))

        passed = False
        try:
            base = args.preproxy
            ok, exit_info, reasons, path = verify_candidate(proxy, country, base, L.out)
            if not ok and not exit_info and base is None:
                # gateway host unreachable directly -> retry via local xray
                base = LOCAL_PREPROXY
                L.out("gateway unreachable directly - retrying via preproxy", base)
                ok, exit_info, reasons, path = verify_candidate(proxy, country, base, L.out)
            if ok:
                ok, details = stability_tests(proxy, path, base, L.out)
            if ok:
                info = exit_info
                L.out("=== PASS ===")
                L.out("exit IP:", info.get("query"),
                      "| city:", info.get("city"), "| region:", info.get("regionName"))
                L.out("ISP:", info.get("isp"), "| org:", info.get("org"))
                L.out("AS:", info.get("as"), "| proxy:", info.get("proxy"),
                      "| hosting:", info.get("hosting"))
                state["last_success"] = {
                    "client_id": proxy["client_id"],
                    "provider_client_id": proxy["provider_client_id"],
                    "host": proxy["host"], "port": proxy["port"],
                    "auth_token": proxy["auth_token"],
                    "http_port": proxy.get("http_port"),
                    "path": path,
                    "exit": exit_info, "details": details,
                    "drawn_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                L.save_state(state)
                txt_path, xray_path, name = L.write_deliverables(
                    proxy, exit_info, details.get("speed", {}).get("mbps", 0), details)
                L.out("deliverable txt:", txt_path)
                L.out("xray config:", xray_path)
                L.out("node name:", name)
                passed = True
                return 0
            reasons = reasons or ["stability tests failed: %s" % json.dumps(details, ensure_ascii=False)]
            L.out("FAIL:", "; ".join(str(r) for r in reasons))
        finally:
            # remove failed candidates only - a PASSING proxy must survive
            if not passed:
                L.out("removing failed proxy client_id=", proxy["client_id"])
                remove_proxy(api_key, proxy["client_id"])
            tried.append(pcid)
            state.setdefault("tried_provider_client_ids", tried)
            L.save_state(state)
            time.sleep(1)

    L.out("round done: %d tried, none passed. Report honestly, do not retry "
          "endlessly (SOP)." % tries)
    return 1


def check(args):
    """Re-verify the kept node from state (--check)."""
    state = L.load_state()
    last = state.get("last_success")
    if not last:
        L.out("no kept node in state")
        return 1
    proxy = {"host": last["host"], "port": last["port"],
             "user": last["auth_token"], "pass": "x"}
    L.register_secret(last["auth_token"])
    L.out("checking node drawn at", last.get("drawn_at"),
          "provider", last.get("provider_client_id"))
    info1 = L.ipapi_via_socks(proxy, args.preproxy)
    ok, reasons = L.judge_exit(info1, args.country)
    L.out("exit now:", (info1 or {}).get("query"),
          (info1 or {}).get("city"), (info1 or {}).get("isp"))
    if not ok:
        L.out("FAIL now:", "; ".join(reasons))
        L.out("provider likely offline -> re-draw (SOP: never try to repair).")
        return 1
    L.out("still PASS (double-false holds)")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--country", default="us")
    ap.add_argument("--tries", type=int, default=5)
    ap.add_argument("--count", type=int, default=50)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--clean", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--preproxy", default=None,
                    help="e.g. socks5h://127.0.0.1:10808 - chain gateway "
                         "tests through this first hop")
    args = ap.parse_args()
    return check(args) if args.check else draw(args)


if __name__ == "__main__":
    sys.exit(main())
