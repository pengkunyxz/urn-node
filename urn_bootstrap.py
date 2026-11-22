"""Fully automated URnetwork account bootstrap using a disposable mailbox.

Verified flow (2026-11-22, live-tested end to end):
  1. mail.tm mailbox (browser UA required; transient CF blocks need retry)
  2. POST /auth/network-create {user_auth, password, network_name, terms:true,
     product_updates:false}        -> verification_required + code email
     (NOTE: /auth/login does NOT send codes to new emails - it only echoes
      user_auth; /auth/verify-send refuses unknown accounts with 400
      "Invalid login". network-create is the only signup door.)
  3. the code arrives from support@ur.io with subject
     "<8-char alnum> is your URnetwork verification code" - alphanumeric,
     NOT numeric-only; parse it from the subject.
  4. POST /auth/verify {user_auth, verify_code}     -> network.by_jwt
  5. POST /account/api-key {name} (Bearer by_jwt)   -> api_key (urn_...)

Re-login without the mailbox (what GitHub Actions will use):
  POST /auth/login-with-password {user_auth, password} -> network.by_jwt

Credentials (mailbox password + api_key) are stored ONLY in
urn_credentials.json (mode 600) and are never printed.
"""
import json
import random
import re
import string
import sys
import time

import requests

import urn_lib as L

MAILTM_API = "https://api.mail.tm"

BROWSER_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/126.0 Safari/537.36"),
    "Accept": "application/json",
}


def _rand(n, chars=string.ascii_lowercase + string.digits):
    rng = random.SystemRandom()
    return "".join(rng.choice(chars) for _ in range(n))


def _hydra(data):
    """mail.tm mixes bare arrays and hydra-wrapped collections."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        v = data.get("hydra:member")
        if isinstance(v, list):
            return v
        for x in data.values():
            if isinstance(x, list):
                return x
    return []


def _get_json(url, headers=None, timeout=30, attempts=3):
    h = dict(BROWSER_HEADERS)
    if headers:
        h.update(headers)
    last = None
    for i in range(attempts):
        try:
            r = requests.get(url, headers=h, timeout=timeout)
            return r.json()
        except ValueError as exc:
            last = exc
            time.sleep(2 + 2 * i)
    raise RuntimeError("non-JSON response from %s (%s)" % (url[:60], last))


def _post_json(url, body, headers=None, timeout=30, attempts=3):
    h = dict(BROWSER_HEADERS)
    h["Content-Type"] = "application/json"
    if headers:
        h.update(headers)
    for i in range(attempts):
        try:
            r = requests.post(url, headers=h, json=body, timeout=timeout)
            if r.status_code in (429, 502, 503):
                time.sleep(3 + 3 * i)
                continue
            return r
        except requests.RequestException:
            time.sleep(2 + 2 * i)
    raise RuntimeError("POST failed %s" % url[:60])


# ------------------------------------------------------------ mail.tm

def mailbox_mailtm():
    domain = _hydra(_get_json(MAILTM_API + "/domains?page=1"))
    domain = next((d["domain"] for d in domain if d.get("isActive")), None)
    if not domain:
        raise RuntimeError("no active mail.tm domain")
    password = _rand(16) + "Aa1!"
    address = "urnbot%s@%s" % (_rand(10), domain)
    r = _post_json(MAILTM_API + "/accounts", {"address": address,
                                              "password": password})
    if r.status_code not in (200, 201):
        raise RuntimeError("mail.tm create %s: %s" % (r.status_code,
                                                      r.text[:120]))
    r = _post_json(MAILTM_API + "/token", {"address": address,
                                           "password": password})
    if not r.ok:
        raise RuntimeError("mail.tm token %s" % r.status_code)
    tok = r.json()["token"]
    L.register_secret(password)
    hdr = {"Authorization": "Bearer " + tok}

    def poll():
        out = []
        try:
            msgs = _hydra(_get_json(MAILTM_API + "/messages?page=1", hdr))
            for m in msgs:
                body = _get_json(MAILTM_API + "/messages/%s" % m.get("id"), hdr)
                out.append({
                    "id": m.get("id"),
                    "from": ((m.get("from") or {}).get("address") or ""),
                    "subject": m.get("subject") or "",
                    "text": body.get("text") or "",
                })
        except Exception as exc:
            L.out("mail.tm poll error:", L.redact(str(exc))[:120])
        return out

    class Box:
        provider = "mail.tm"
        address = address
        mail_password = password
        poll = staticmethod(poll)

    return Box()


def wait_for_code(mb, deadline):
    """BringYour codes: subject '<8 alnum> is your URnetwork verification
    code' (alphanumeric, NOT numeric-only)."""
    seen = set()
    while time.time() < deadline:
        for m in mb.poll():
            if m.get("id") in seen:
                continue
            seen.add(m.get("id"))
            frm = (m.get("from") or "").lower()
            L.out("mail:", frm, "|", (m.get("subject") or "")[:70])
            if "ur.io" not in frm and "bringyour" not in frm \
                    and "urnetwork" not in frm:
                continue
            msubj = re.match(r"^([0-9a-zA-Z]{8}) is your", m.get("subject") or "")
            if msubj:
                return msubj.group(1)
            codes = re.findall(r"\b([0-9a-zA-Z]{8})\b", m.get("text") or "")
            if codes:
                return codes[0]
        time.sleep(6)
    return None


# ------------------------------------------------------------ main flow

def bootstrap(force=False):
    cred = L.load_json_file(L.CRED_FILE)
    if cred.get("api_key") and not force:
        L.out("credentials already exist in", L.CRED_FILE,
              "- nothing to do (use force to re-register)")
        return 0

    mb = mailbox_mailtm()
    L.out("== mailbox:", mb.address, "(%s)" % mb.provider)

    netname = "urnbot" + _rand(10)
    L.out("creating network:", netname)
    data = L.api_call("POST", "/auth/network-create", {
        "user_auth": mb.address,
        "password": mb.mail_password,
        "network_name": netname,
        "terms": True,
        "product_updates": False,
        "result_errors": True,
    })
    err = L.api_error(data)
    if err:
        L.out("network-create refused:", err.get("message"))
        return 1
    if not data.get("verification_required"):
        L.out("no verification_required; keys:", sorted(data.keys()))
        return 1
    L.out("verification required - code email sent")

    code = wait_for_code(mb, time.time() + 240)
    if not code:
        L.out("ERROR: no code arrived within 4 min")
        return 1
    L.out("code received (length %d)" % len(code))

    vdata = L.api_call("POST", "/auth/verify",
                       {"user_auth": mb.address, "verify_code": code})
    verr = L.api_error(vdata)
    if verr:
        L.out("verify failed:", verr.get("message"))
        return 1
    jwt = ((vdata.get("network") or {}).get("by_jwt") or "")
    if not jwt:
        L.out("verify returned no JWT; keys:",
              json.dumps(L.sanitize_json(vdata), ensure_ascii=False)[:250])
        return 1
    L.register_secret(jwt)
    L.out("verified OK")

    kdata = L.api_call("POST", "/account/api-key",
                       {"name": "urn-draw-agent-%s" % time.strftime("%Y%m%d")},
                       token=jwt)
    kerr = L.api_error(kdata)
    if kerr:
        L.out("api-key create failed:", kerr.get("message"))
        return 1
    api_key = kdata.get("api_key") or ""
    key_id = kdata.get("id") or ""
    if not api_key.startswith("urn_"):
        L.out("unexpected api-key response:",
              json.dumps(L.sanitize_json(kdata), ensure_ascii=False)[:250])
        return 1
    L.register_secret(api_key)

    # sanity: password re-login must work (this is what GHA will use)
    pdata = L.api_call("POST", "/auth/login-with-password",
                       {"user_auth": mb.address,
                        "password": mb.mail_password,
                        "result_errors": True})
    perr = L.api_error(pdata)
    if perr or not ((pdata.get("network") or {}).get("by_jwt")):
        L.out("WARN: login-with-password check failed",
              (perr or {}).get("message", ""))

    L.save_json_file(L.CRED_FILE, {
        "api_key": api_key,
        "key_id": key_id,
        "email": mb.address,
        "email_provider": mb.provider,
        "email_password": mb.mail_password,
        "network_name": netname,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    L.out("OK: registered, api_key stored in", L.CRED_FILE)
    L.out("account email:", mb.address, "| network:", netname)
    return 0


def relogin():
    """Password re-login -> fresh network JWT (for GHA). JWT is returned to
    the caller (in-memory); never printed."""
    cred = L.load_json_file(L.CRED_FILE)
    data = L.api_call("POST", "/auth/login-with-password",
                      {"user_auth": cred.get("email"),
                       "password": cred.get("email_password"),
                       "result_errors": True})
    jwt = ((data.get("network") or {}).get("by_jwt") or "")
    if not jwt:
        err = L.api_error(data)
        raise RuntimeError("login-with-password failed: %s"
                           % (err or {}).get("message", data.get("_raw", "")))
    L.register_secret(jwt)
    return jwt


if __name__ == "__main__":
    sys.exit(bootstrap("--force" in sys.argv))
