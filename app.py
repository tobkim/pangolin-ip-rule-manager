import base64
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

# Config via environment
PANGOLIN_URL = os.getenv("PANGOLIN_URL", "https://api.url.of.your.pangolin.instance").rstrip("/")
PANGOLIN_TOKEN = os.getenv("PANGOLIN_TOKEN", "")
ORG_ID = os.getenv("ORG_ID", "your_org_id")
RESOURCE_IDS = [int(x) for x in os.getenv("RESOURCE_IDS", "2,7,12").split(",") if x.strip()]
RETENTION_MINUTES = int(os.getenv("RETENTION_MINUTES", "1440"))  # default 1 day in minutes
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
STATE_FILE = os.getenv("STATE_FILE", "/data/state.json")
CLEANUP_INTERVAL_MINUTES = int(os.getenv("CLEANUP_INTERVAL_MINUTES", "60"))  # default 1 hour in minutes
RULE_PRIORITY = int(os.getenv("RULE_PRIORITY", "0"))
RULES_CACHE_TTL_SECONDS = int(os.getenv("RULES_CACHE_TTL_SECONDS", "3600"))  # cache for existence checks (~1h)
# Mandatory Pangolin custom header gate: both must be set and non-empty
EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY = os.getenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", "").strip()
EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE = os.getenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", "").strip()
if not EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY or not EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE:
    raise RuntimeError("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY and EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE must be set and non-empty")

# Minimal 1x1 PNG (transparent) as bytes
BANNER_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII="
)

state_lock = threading.Lock()
state = {
    # ip: {
    #   "last_seen": "2025-01-01T00:00:00Z",
    #   "resources": {"2": {"created_by_us": true}, ...}
    # }
}

# In-memory cache: per resourceId set of IPs known to have a rule, with TTL
rules_cache = {
    # rid: {"ts": epoch_seconds, "ip_set": set([...])}
}


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_state():
    global state
    if not os.path.exists(STATE_FILE):
        return
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            state = data
    except Exception as e:
        print(f"[state] failed to load state: {e}")


def save_state():
    tmp_file = STATE_FILE + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)
        os.replace(tmp_file, STATE_FILE)
    except Exception as e:
        print(f"[state] failed to save state: {e}")


def http_json(method: str, url: str, body: dict | None = None) -> dict:
    headers = {
        "Authorization": f"Bearer {PANGOLIN_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=20) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            text = resp.read().decode(charset, errors="replace")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text}
    except HTTPError as e:
        try:
            err = e.read().decode("utf-8", errors="replace")
        except Exception:
            err = str(e)
        raise RuntimeError(f"HTTP {e.code} {e.reason}: {err}")
    except URLError as e:
        raise RuntimeError(f"Network error: {e}")


def _get_ip_set_for_resource_cached(rid: int):
    """Return a set of IPs that currently have a rule for the resource.
    Uses a 1h TTL cache to avoid frequent GET calls."""
    now = time.time()
    with state_lock:
        entry = rules_cache.get(rid)
        if entry and (now - entry.get("ts", 0) < RULES_CACHE_TTL_SECONDS):
            return entry.get("ip_set", set())
    # Refresh from Pangolin
    print(f"[pangolin] refreshing rules for resource {rid}")
    rules_resp = http_json("GET", f"{PANGOLIN_URL}/v1/resource/{rid}/rules?limit=10000")
    rules = rules_resp.get("data", {}).get("rules", [])
    ip_set = set()
    for r in rules:
        if r.get("match") == "IP":
            v = r.get("value")
            if isinstance(v, str):
                ip_set.add(v)
    with state_lock:
        rules_cache[rid] = {"ts": now, "ip_set": ip_set}
    return ip_set


def ensure_ip_rule(ip: str) -> None:
    if not PANGOLIN_TOKEN:
        print("[warn] No PANGOLIN_TOKEN set; skipping Pangolin API calls.")
        return
    for rid in RESOURCE_IDS:
        try:
            # 1) check cached existence
            ip_set = _get_ip_set_for_resource_cached(rid)
            if ip in ip_set:
                print(f"[pangolin] rule already exists for IP {ip} on resource {rid}")
                # Track presence but not created_by_us
                with state_lock:
                    rec = state.setdefault(ip, {"last_seen": now_utc_iso(), "resources": {}})
                    rec["last_seen"] = now_utc_iso()
                    rec["resources"].setdefault(str(rid), {"created_by_us": False})
                continue
            # 2) create rule
            payload = {
                "action": "ACCEPT",
                "match": "IP",
                "value": ip,
                "priority": RULE_PRIORITY,
                "enabled": True,
            }
            _ = http_json("PUT", f"{PANGOLIN_URL}/v1/resource/{rid}/rule", payload)
            print(f"[pangolin] created rule for IP {ip} on resource {rid}")
            # Update cache to include newly created rule
            with state_lock:
                entry = rules_cache.get(rid)
                if entry:
                    entry.setdefault("ip_set", set()).add(ip)
                    # keep original ts; it's fine for existence cache
                else:
                    rules_cache[rid] = {"ts": time.time(), "ip_set": {ip}}
            # Update persistent state
            with state_lock:
                rec = state.setdefault(ip, {"last_seen": now_utc_iso(), "resources": {}})
                rec["last_seen"] = now_utc_iso()
                rec["resources"][str(rid)] = {"created_by_us": True}
            save_state()
        except Exception as e:
            print(f"[pangolin] ensure rule failed for resource {rid}, ip {ip}: {e}")


def delete_ip_rule_if_created_by_us(ip: str, rid: int) -> bool:
    """Returns True if a deletion was performed, False otherwise."""
    try:
        rules_resp = http_json(
            "GET", f"{PANGOLIN_URL}/v1/resource/{rid}/rules?limit=10000"
        )
        rules = rules_resp.get("data", {}).get("rules", [])
        to_delete = [r for r in rules if r.get("match") == "IP" and r.get("value") == ip]
        deleted_any = False
        for r in to_delete:
            rule_id = r.get("ruleId")
            if rule_id is None:
                continue
            try:
                _ = http_json(
                    "DELETE", f"{PANGOLIN_URL}/v1/resource/{rid}/rule/{rule_id}"
                )
                print(f"[pangolin] deleted rule {rule_id} for IP {ip} on resource {rid}")
                deleted_any = True
            except Exception as e:
                print(f"[pangolin] delete failed for rule {rule_id} on {rid}: {e}")
        return deleted_any
    except Exception as e:
        print(f"[pangolin] fetch rules (delete phase) failed for {rid}, ip {ip}: {e}")
        return False


def cleanup_old_ips():
    print("[cleanup] starting")
    print("current ips allowed:" , str(state))
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=RETENTION_MINUTES)
    with state_lock:
        ips = list(state.keys())
    for ip in ips:
        with state_lock:
            rec = state.get(ip) or {}
            last_seen_str = rec.get("last_seen")
            resources = rec.get("resources", {})
        try:
            last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00")) if last_seen_str else None
        except Exception:
            last_seen = None
        if not last_seen or last_seen > cutoff:
            continue
        # Time to cleanup per resource if created_by_us
        changed = False
        for rid_str, meta in list(resources.items()):
            rid = int(rid_str)
            if not meta.get("created_by_us"):
                continue
            if delete_ip_rule_if_created_by_us(ip, rid):
                # Remove our reference
                with state_lock:
                    rec2 = state.get(ip)
                    if rec2 and rid_str in rec2.get("resources", {}):
                        rec2["resources"].pop(rid_str, None)
                        changed = True
        # If no resources remain, drop the IP record
        with state_lock:
            rec3 = state.get(ip)
            if rec3 and not rec3.get("resources"):
                state.pop(ip, None)
                changed = True
        if changed:
            save_state()
        print(f"[cleanup] removed {ip} (last_seen={last_seen_str})")
    print("[cleanup] done")


def cleanup_loop():
    while True:
        try:
            cleanup_old_ips()
        except Exception as e:
            print(f"[cleanup] unexpected error: {e}")
        time.sleep(CLEANUP_INTERVAL_MINUTES*60)


class BannerHandler(BaseHTTPRequestHandler):
    server_version = "BannerServer/1.0"

    def log_message(self, fmt, *args):
        # Minimal console logging
        print("[http]", self.address_string(), "-", fmt % args)

    def _get_real_ip(self) -> str:
        # precedence: X-Real-IP, X-Forwarded-For (first), fallback to client addr
        xr = self.headers.get("X-Real-IP")
        if xr:
            return xr.strip()
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def do_GET(self):
        ip = self._get_real_ip()

        remote_user = self.headers.get("Remote-User","")

        # Log all request headers
        print("New request from", ip, " user:", remote_user, "Headers: ", json.dumps({k: v for k, v in self.headers.items()}))

        # Enforce Pangolin custom header (mandatory)
        actual = self.headers.get(EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY)
        if actual is None or actual != EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Forbidden: missing or invalid Pangolin custom header")
            return

        parsed = urlparse(self.path)
        if parsed.path != "/banner.png":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
            return

        # Update state and ensure rules
        with state_lock:
            rec = state.setdefault(ip, {"last_seen": now_utc_iso(), "resources": {}})
            rec["last_seen"] = now_utc_iso()
        save_state()

        # Perform Pangolin call synchronously (simple, small scale)
        try:
            ensure_ip_rule(ip)
        except Exception as e:
            print(f"[error] ensure_ip_rule failed for {ip}: {e}")

        # Serve PNG
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(BANNER_PNG)))
        self.end_headers()
        self.wfile.write(BANNER_PNG)


def self_check():
    # Double-check mandatory environment settings and print useful warnings/summary.
    missing = []
    if not EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY:
        missing.append("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY")
    if not EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE:
        missing.append("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE")
    if missing:
        # Keep behavior aligned with import-time validation, but provide a clear error here as well
        raise RuntimeError(
            "Missing required environment variables: " + ", ".join(missing)
        )

    if not PANGOLIN_TOKEN:
        print("[warn] PANGOLIN_TOKEN is not set; Pangolin API actions will be skipped.")
    if not RESOURCE_IDS:
        print("[warn] RESOURCE_IDS is empty; no resources will be managed.")

    print(
        f"[self-check] OK. listen_port={LISTEN_PORT} state_file={STATE_FILE} "
        f"resources={RESOURCE_IDS} retention_minutes={RETENTION_MINUTES} "
        f"cleanup_interval_minutes={CLEANUP_INTERVAL_MINUTES} rule_priority={RULE_PRIORITY}"
    )


def print_org_resources():
    try:
        url = f"{PANGOLIN_URL}/v1/org/{ORG_ID}/resources?limit=1000&offset=0"
        resp = http_json("GET", url)
        resources = (
            resp.get("data", {}).get("resources")
            if isinstance(resp, dict)
            else []
        ) or resp.get("resources", []) or []
        print(f"[pangolin] These are the resources for org '{ORG_ID}'. Use the resourceId numbers for your configuration:")
        if not resources:
            print("  (no resources found or empty response)")
            return
        for r in resources:
            name = r.get("name") or r.get("resourceName") or "(no-name)"
            rid = r.get("resourceId") or r.get("id")
            print(f"  - {name} (resourceId={rid})")
    except Exception as e:
        print(f"[pangolin] failed to list resources for org {ORG_ID}: {e}")
        raise e


def main():
    self_check()
    load_state()
    # Fetch and print resources for the configured org (helper for selecting resource IDs)
    print_org_resources()

    # Start cleanup thread
    t = threading.Thread(target=cleanup_loop, daemon=True)
    t.start()

    addr = ("0.0.0.0", LISTEN_PORT)
    httpd = HTTPServer(addr, BannerHandler)
    print(f"[start] Listening on {addr[0]}:{addr[1]} | resources={RESOURCE_IDS} | retention_minutes={RETENTION_MINUTES} | cleanup_interval_minutes={CLEANUP_INTERVAL_MINUTES}")

    httpd.serve_forever()


if __name__ == "__main__":
    main()
