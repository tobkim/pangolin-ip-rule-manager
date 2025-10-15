# Pangolin IP Rule Manager

> A tiny Dockerized web server that serves a single file (banner.png) and, on each request, ensures the requester's IP has an ACCEPT rule in Pangolin VPN across configured resources. It persists a small hashmap of seen IPs and periodically deletes rules created by this service if the IP has not been seen for a configurable number of minutes.

Tested with Pangolin v1.10.3.

---

## Important Warning
- You are responsible for securing access to this service via Pangolin (and/or your reverse proxy). Do NOT expose it publicly without strict Pangolin ACLs limiting who can reach `/banner.png`.
- Keep your `PANGOLIN_TOKEN` secret and rotate it periodically.

---

## Overview
This service exposes a single endpoint, `GET /banner.png`, returning a 1×1 transparent PNG. Each request is treated as a heartbeat from the client's IP address, prompting rule creation (if needed) in Pangolin for configured resources. A background task cleans up rules created by this service if the IP hasn't been seen for a configurable period.

---

## Key Properties
- Extremely small and simple: Python stdlib only, no external dependencies
- Single endpoint: `GET /banner.png` returns a 1×1 transparent PNG
- Security enforcement:
  - `Remote-User` header is always required
  - Optional custom header (see EXPECTED_PANGOLIN_HEADER_KEY/EXPECTED_PANGOLIN_HEADER_VALUE) can additionally be enforced if configured
- IP extraction from `X-Real-IP`, then `X-Forwarded-For`, then socket address
- Pangolin API integration: GET current rules, PUT to add, DELETE to remove
- Persistent state: JSON file (default at `/data/state.json`, persisted via a Docker volume in the provided compose file)
- Background cleanup thread removes stale rules created by this service

---

## Configuration (environment variables)
- `PANGOLIN_URL`: Base URL of Pangolin API (default: `https://api.url.of.your.pangolin.instance`)
- `PANGOLIN_TOKEN`: Bearer token for Pangolin API (required for API actions)
- `ORG_ID`: Pangolin organization identifier used to list resources at startup (default: `your_org_id`)
- `RESOURCE_IDS`: Comma-separated resource IDs (example: `2,7,12`)
- `RETENTION_MINUTES`: Minutes without seeing an IP before cleanup deletes rules (default: `1440` = 1 day)
- `LISTEN_PORT`: HTTP listen port (default: `8080`)
- `STATE_FILE`: Path to JSON state file (default: `/data/state.json`)
- `CLEANUP_INTERVAL_MINUTES`: Cleanup frequency in minutes (default: `60` = 1 hour)
- `RULE_PRIORITY`: Rule priority when creating rules (default: `0`)
- `RULES_CACHE_TTL_SECONDS`: Seconds to cache rule-existence checks per resource (default: `3600`)
- `EXPECTED_PANGOLIN_HEADER_KEY`: Optional. If set together with EXPECTED_PANGOLIN_HEADER_VALUE, incoming requests must include this header key with the exact value.
- `EXPECTED_PANGOLIN_HEADER_VALUE`: Optional. See above. Configure the same header in Pangolin on the resource fronting this service.

---

## Run with Docker Compose (recommended)
1) Clone this repository and change into the directory

```bash
git clone https://github.com/tobkim/pangolin-ip-rule-manager.git
cd pangolin-ip-rule-manager
```

2) Copy config.env.sample to config.env and update the values.
  - PANGOLIN_URL: Your Pangolin API base URL
  - ORG_ID: Your Pangolin organization ID (string)
  - PANGOLIN_TOKEN: API token with the required permissions (see below)
  - RESOURCE_IDS: Comma-separated list of resource IDs to manage (e.g., 2,7,12). The available resource ids cannot be seen anymore in the newer pangolin versions. They are listed in the logs at the start of the container to help you out.

3) Start the service

```bash
docker compose up -d
```

4) configure a new resource in Pangolin and point it to this container, e.g. a subdomain checkin.yourdomain.com 

5) access https://checkin.yourdomain.com/banner.png. Your IP should now be in the list of allowed IPs.

---

---

## Behavior
- On startup, the service fetches and prints the list of resources for `ORG_ID` from Pangolin, showing name and `resourceId` to help you choose `RESOURCE_IDS`.
- If `Remote-User` is missing, returns `403`.
- If `EXPECTED_PANGOLIN_HEADER_KEY` and `EXPECTED_PANGOLIN_HEADER_VALUE` are both set and the incoming request either lacks the header or has a different value, returns `403`.
- On each successful request, the real IP is determined and this service:
  - Updates `last_seen` for that IP in the state file
  - Checks Pangolin rules for each `resourceId` and creates one if missing (rule-existence checks are cached per resource for about 1 hour, configurable)
  - Serves a tiny PNG image
- A background task periodically deletes rules for IPs that this service created once they have not been seen for `RETENTION_MINUTES` minutes.

---

## Notes
- Only rules created by this service are deleted during cleanup. Existing rules discovered as already present are left intact.
- The state is persisted to a JSON file at `STATE_FILE` (default `/data/state.json`). The provided `docker-compose.yml` uses a named volume to persist this data across restarts. You can change or remove the volume mapping if you prefer ephemeral state.

---

## API key permissions (what the token needs)
Make sure the API token you configure has the following minimal permissions:
- Ability to list resources in the organization (read-only)
- Ability to list existing access rules for the specified resources
- Ability to create and delete IP-based access rules for those resources

If your Pangolin setup allows scoping tokens to specific resources, restrict the token to only the `RESOURCE_IDS` you will manage.

The following screenshot shows the needed permissions to select:

![Pangolin API key permissions](pangolin-api-key-permissions.png)


---

## Integrating via CSS (e.g., Jellyfin)
You can trigger the invisible request to `/banner.png` from web apps (like Jellyfin) using a tiny CSS snippet. This keeps the page unchanged while causing the browser to fetch the image, which lets this service observe the requester IP and manage Pangolin rules.

Replace `https://your-pangolin-ip-rule-manager-domain.com` with your real domain pointing to this service.

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

---

### Disclaimer: AI-generated
- This project was created and is largely maintained with the help of AI assistants. While kept intentionally simple and reviewed for practicality and safety, it may contain mistakes or omissions.
- Always review the code, configuration, and security posture before deploying to production. Use at your own risk.
- Contributions, bug reports, and human review are highly encouraged.

