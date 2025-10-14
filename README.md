Pangolin IP Rule Manager

IMPORTANT WARNING
- You are responsible for securing access to this service via Pangolin (and/or your reverse proxy). Do NOT expose it publicly without strict Pangolin ACLs limiting who can reach /banner.png.
- Keep your PANGOLIN_TOKEN secret and rotate it periodically.

A tiny Dockerized web server that serves a single file (banner.png) and, on each request, ensures the requester's IP has an ACCEPT rule in Pangolin VPN across configured resources. It persists a small hashmap of seen IPs and periodically deletes rules created by this service if the IP has not been seen for a configurable number of minutes.

Tested with Pangolin v1.10.3.

Disclaimer: AI-generated
- This project was created and is largely maintained with the help of AI assistants. While kept intentionally simple and reviewed for practicality and safety, it may contain mistakes or omissions.
- Always review the code, configuration, and security posture before deploying to production. Use at your own risk.
- Contributions, bug reports, and human review are highly encouraged.

Key properties
- Extremely small and simple: Python stdlib only, no external dependencies
- Single endpoint: GET /banner.png returns a 1×1 transparent PNG
- Security header check: Remote-User header is always required
- IP extraction from X-Real-IP, then X-Forwarded-For, then socket address
- Pangolin API integration: GET current rules, PUT to add, DELETE to remove
- Persistent state: JSON file (default at /data/state.json, persisted via a Docker volume in the provided compose file)
- Background cleanup thread removes stale rules created by this service

Configuration (environment variables)
- PANGOLIN_URL: Base URL of Pangolin API (default: https://api.url.of.your.pangolin.instance)
- PANGOLIN_TOKEN: Bearer token for Pangolin API (required for API actions)
- ORG_ID: Pangolin organization identifier used to list resources at startup (default: your_org_id)
- RESOURCE_IDS: Comma-separated resource IDs (example: 2,7,12).
- RETENTION_MINUTES: Minutes without seeing an IP before cleanup deletes rules (default: 1440 = 1 day)
- LISTEN_PORT: HTTP listen port (default: 8080)
- STATE_FILE: Path to JSON state file (default: /data/state.json)
- CLEANUP_INTERVAL_MINUTES: Cleanup frequency in minutes (default: 60 = 1 hour)
- RULE_PRIORITY: Rule priority when creating rules (default: 0)
- RULES_CACHE_TTL_SECONDS: Seconds to cache rule-existence checks per resource (default: 3600)
Run locally (Docker)
1) Build the image
   docker build -t pangolin-ip-rule-manager .

2) Run the container
   docker run -e PANGOLIN_TOKEN=REPLACE_ME \
              -e RESOURCE_IDS=2,7,12 \
              -e RETENTION_MINUTES=10080 \
              -p 8080:8080 \
              --name pangolin-ip-rule-manager \
              pangolin-ip-rule-manager

3) Make a request (simulate reverse proxy headers):
   curl -v http://localhost:8080/banner.png \
        -H "Remote-User: alice" \
        -H "X-Real-IP: 203.0.113.45"

Behavior
- On startup, the service fetches and prints the list of resources for ORG_ID from Pangolin, showing name and resourceId to help you choose RESOURCE_IDS.
- If Remote-User is missing, returns 403.
- On each successful request, the real IP is determined and this service:
  - Updates last_seen for that IP in the state file
  - Checks Pangolin rules for each resourceId and creates one if missing
    (rule-existence checks are cached per resource for about 1 hour, configurable)
  - Serves a tiny PNG image
- A background task periodically deletes rules for IPs that this service created
  once they have not been seen for RETENTION_MINUTES minutes.

Notes
- Only rules created by this service are deleted during cleanup. Existing rules
  discovered as already present are left intact.
- The state is persisted to a JSON file at STATE_FILE (default /data/state.json).
  The provided docker-compose.yml uses a named volume to persist this data across restarts.
  You can change or remove the volume mapping if you prefer ephemeral state.

License
MIT




Integrating via CSS (e.g., Jellyfin)
You can trigger the invisible request to /banner.png from web apps (like Jellyfin) using a tiny CSS snippet. This keeps the page unchanged while causing the browser to fetch the image, which lets this service observe the requester IP and manage Pangolin rules.

CSS example
Replace https://your-pangolin-ip-rule-manager-domain.com with your real domain pointing to this service.

```css
body::after {
  content: "";
  position: fixed;
  inset: -9999px;           /* keep it far off-screen */
  width: 1px;
  height: 1px;
  pointer-events: none;
  background-image: url("https://your-pangolin-ip-rule-manager-domain.com/banner.png");
  background-repeat: no-repeat;
}
```

