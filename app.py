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

from crowdsec_connector import (
    crowdsec_add_ip,
    crowdsec_remove_ip,
    crowdsec_ensure_allowlist,
)
from pangolin_connector import (
    PangolinContext,
    get_ip_set_for_resource_cached as pg_get_ip_set_for_resource_cached,
    ensure_ip_rule as pg_ensure_ip_rule,
    delete_ip_rule_if_created_by_us as pg_delete_ip_rule_if_created_by_us,
    list_org_resources as pg_list_org_resources,
)

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
# CrowdSec optional integration via cscli
CROWDSEC_ENABLED = os.getenv("CROWDSEC_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")
CROWDSEC_CSCLI_BIN = os.getenv("CROWDSEC_CSCLI_BIN", "cscli").strip()
# Optional: a command prefix to run cscli in a container, e.g. "docker exec crowdsec"
CROWDSEC_CMD_PREFIX = os.getenv("CROWDSEC_CMD_PREFIX", "").strip()
CROWDSEC_ALLOWLIST_NAME = os.getenv("CROWDSEC_ALLOWLIST_NAME", "pangolin-ip-rule-manager").strip()
CROWDSEC_CACHE_TTL_SECONDS = int(os.getenv("CROWDSEC_CACHE_TTL_SECONDS", "3600"))  # cache TTL for CrowdSec allowlist entries (~1h)
# Mandatory Pangolin custom header gate: both must be set and non-empty
EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY = os.getenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", "").strip()
EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE = os.getenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", "").strip()
if not EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY or not EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE:
    raise RuntimeError("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY and EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE must be set and non-empty")

# Minimal 1x1 PNG (transparent) as bytes
BANNER_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII="
)
# Minimal 1x1 GIF (transparent) as bytes
BANNER_GIF = base64.b64decode(
    "R0lGODlhAQABAPAAAP///wAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw=="
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

# CrowdSec runtime flags/caches
_crowdsec_allowlist_ready = False
# Cache of IPs currently in the CrowdSec allowlist (with TTL)
crowdsec_cache = {"ts": 0.0, "ip_set": set()}


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def redact_headers_for_log(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers suitable for logging.
    - Redacts Authorization/Proxy-Authorization values
    - Masks the expected Pangolin custom header value to avoid leaking secrets
    Header names are matched case-insensitively.
    """
    redacted: dict[str, str] = {}
    expected_key_lower = EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY.lower() if EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY else None
    for k, v in headers.items():
        kl = k.lower()
        if kl in ("authorization", "proxy-authorization"):
            redacted[k] = "<redacted>"
        elif expected_key_lower and kl == expected_key_lower:
            # Don't log secret value; only indicate presence
            redacted[k] = "<present>" if v else "<missing>"
        else:
            redacted[k] = v
    return redacted


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





# Targets common interface
class Target:
    def ensure_ready(self) -> None:
        pass

    def add_ip(self, ip: str) -> None:
        raise NotImplementedError

    def expire_ip(self, ip: str) -> None:
        pass


class PangolinTarget(Target):
    def __init__(self, ctx_factory):
        self._ctx_factory = ctx_factory

    def add_ip(self, ip: str) -> None:
        ctx = self._ctx_factory()
        pg_ensure_ip_rule(ctx, ip)

    # Pangolin cleanup is handled separately based on created_by_us; no generic expire here.
    def expire_ip(self, ip: str) -> None:
        return


class CrowdSecTarget(Target):
    def ensure_ready(self) -> None:
        crowdsec_ensure_allowlist()

    def add_ip(self, ip: str) -> None:
        crowdsec_add_ip(ip)

    def expire_ip(self, ip: str) -> None:
        crowdsec_remove_ip(ip)


def make_pangolin_context() -> PangolinContext:
    return PangolinContext(
        url=PANGOLIN_URL,
        token=PANGOLIN_TOKEN,
        resource_ids=RESOURCE_IDS,
        rule_priority=RULE_PRIORITY,
        rules_cache_ttl_seconds=RULES_CACHE_TTL_SECONDS,
        rules_cache=rules_cache,
        state=state,
        state_lock=state_lock,
        save_state=save_state,
        now_utc_iso=now_utc_iso,
        http_json=http_json,
    )


# Register targets
TARGETS: list[Target] = [PangolinTarget(make_pangolin_context)]
if CROWDSEC_ENABLED:
    TARGETS.append(CrowdSecTarget())


def _get_ip_set_for_resource_cached(rid: int):
    """Return a set of IPs that currently have a rule for the resource.
    Uses a 1h TTL cache to avoid frequent GET calls."""
    ctx = make_pangolin_context()
    return pg_get_ip_set_for_resource_cached(ctx, rid)


def ensure_ip_rule(ip: str) -> None:
    ctx = make_pangolin_context()
    pg_ensure_ip_rule(ctx, ip)


# --------------------------
# Target aggregation (extensibility point)
# --------------------------

def add_ip_to_targets(ip: str) -> None:
    """Add/allow this IP across configured targets (Pangolin, CrowdSec, etc.)."""
    for t in TARGETS:
        try:
            t.add_ip(ip)
        except Exception as e:
            print(f"[targets] add failed for {ip} on {t.__class__.__name__}: {e}")


def expire_ip_from_targets(ip: str) -> None:
    """Expire/remove this IP across optional targets when our retention hit."""
    for t in TARGETS:
        try:
            t.expire_ip(ip)
        except Exception as e:
            print(f"[targets] expire failed for {ip} on {t.__class__.__name__}: {e}")


def delete_ip_rule_if_created_by_us(ip: str, rid: int) -> bool:
    ctx = make_pangolin_context()
    return pg_delete_ip_rule_if_created_by_us(ctx, ip, rid)


def cleanup_old_ips():
    print("[cleanup] starting")
    # Avoid dumping the entire state (privacy/noise); log a summary count instead
    with state_lock:
        state_count = len(state)
    print(f"[cleanup] current IPs in state: {state_count}")
    # Use second-level precision to align with stored timestamps (now_utc_iso has no microseconds)
    now_sec = datetime.now(timezone.utc).replace(microsecond=0)
    cutoff = now_sec - timedelta(minutes=RETENTION_MINUTES)
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
        # Skip if record is missing timestamp or not yet expired
        if not last_seen or last_seen >= cutoff:
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
        # Always attempt CrowdSec expiration for expired IPs (idempotent)
        try:
            expire_ip_from_targets(ip)
        except Exception as e:
            print(f"[cleanup] crowdsec expire failed for {ip}: {e}")
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


from image_request_handler import create_image_request_handler


def _make_image_handler_context() -> dict:
    return {
        "expected_header_key": EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY,
        "expected_header_value": EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE,
        "state": state,
        "state_lock": state_lock,
        "now_utc_iso": now_utc_iso,
        "save_state": save_state,
        "add_ip_to_targets": add_ip_to_targets,
        "banner_png": BANNER_PNG,
        "banner_gif": BANNER_GIF,
        "redact_headers_for_log": redact_headers_for_log,
    }


# Expose the HTTP handler class (renamed from BannerHandler)
ImageRequestHandler = create_image_request_handler(_make_image_handler_context())
# Backward compatibility for external users/tests that still reference BannerHandler
BannerHandler = ImageRequestHandler


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

    cs_status = (
        f"enabled name='{CROWDSEC_ALLOWLIST_NAME}' bin='{CROWDSEC_CSCLI_BIN}' prefix='{CROWDSEC_CMD_PREFIX}'"
        if CROWDSEC_ENABLED else "disabled"
    )

    print(
        f"[self-check] OK. listen_port={LISTEN_PORT} state_file={STATE_FILE} "
        f"resources={RESOURCE_IDS} retention_minutes={RETENTION_MINUTES} "
        f"cleanup_interval_minutes={CLEANUP_INTERVAL_MINUTES} rule_priority={RULE_PRIORITY} "
        f"crowdsec={cs_status}"
    )


def print_org_resources():
    ctx = make_pangolin_context()
    pg_list_org_resources(ctx, ORG_ID)


def main():
    self_check()
    load_state()
    # Fetch and print resources for the configured org (helper for selecting resource IDs)
    print_org_resources()

    # Ensure targets are ready (e.g., create CrowdSec allowlist if enabled)
    for t in TARGETS:
        try:
            t.ensure_ready()
        except Exception as e:
            print(f"[targets] ensure_ready failed for {t.__class__.__name__}: {e}")

    # Start cleanup thread
    t = threading.Thread(target=cleanup_loop, daemon=True)
    t.start()

    addr = ("0.0.0.0", LISTEN_PORT)
    httpd = HTTPServer(addr, ImageRequestHandler)
    print(f"[start] Listening on {addr[0]}:{addr[1]} | resources={RESOURCE_IDS} | retention_minutes={RETENTION_MINUTES} | cleanup_interval_minutes={CLEANUP_INTERVAL_MINUTES}")

    httpd.serve_forever()


if __name__ == "__main__":
    main()
