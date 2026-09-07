<p align="center">
  <img src="assets/zentwhook-logo.png" alt="ZentWHook" width="220">
</p>

# ZentWHook

ZentWHook is an open-source, self-hosted **webhook gateway, inspector, transformer, router and replay system** by **ZentWorks**.

It receives HTTP/webhook events, stores and inspects them, evaluates optional conditions, transforms data when needed and delivers requests to one or more HTTP destinations. The product stays deliberately focused on the webhook lifecycle instead of becoming a general workflow platform.

> **Receive → Inspect → Validate → Transform → Route → Deliver → Replay**

## Features

- Incoming webhook endpoints with generated or custom slugs
- Configurable HTTP methods and accepted Content-Types
- Optional Bearer Token, API Key, Basic Auth, HMAC with custom signed payload templates and custom-header authentication
- IP allowlist/denylist with CIDR support
- Per-endpoint rate limits, payload limits and request timeouts
- Trusted proxy support for real client IP handling
- Encrypted storage of event bodies, query strings, header values and configured secrets
- Automatic JSON inspection for strings, numbers, booleans, nulls, objects and arrays
- Webhook-scoped flows and destinations instead of global workflow objects
- Simple **Direct** forwarding with 1:1 request passthrough by default
- **If / Else** routing with AND/OR conditions and common comparison operators
- Visual field mapping with incoming sample events, static values, fallbacks and transformations
- Multiple destinations per route
- Dry Run without external delivery
- Delivery reports with request, response, duration, attempts and errors
- Automatic retries for configured transient failures
- Manual Retry and Edit & Retry
- Replay and Edit & Replay through the normal incoming processing path
- Event search, filters and side-by-side JSON diff
- Configurable event retention
- Import/export of configuration; secrets excluded by default
- REST API under `/api/v1/`
- Local, CDN-free API documentation under `/api/docs`
- Server-side German and English UI
- Responsive Light/Dark interface
- PostgreSQL-backed persistent queue with a separate worker
- Docker-first deployment with health checks
- Multi-architecture GHCR image for `linux/amd64` and `linux/arm64`

# Quick start

The production container image is published to GitHub Container Registry:

```text
ghcr.io/zentworks/zentwhook:latest
```

Docker Compose is the recommended deployment method.

## 1. Docker Compose

Create a directory:

```bash
mkdir zentwhook
cd zentwhook
```

Create `.env`:

```dotenv
HTTP_PORT=8080
APP_BASE_URL=http://localhost:8080
DEFAULT_LANGUAGE=de
LOG_LEVEL=info

POSTGRES_DB=zentwhook
POSTGRES_USER=zentwhook
POSTGRES_PASSWORD=replace-with-a-strong-password

EVENT_RETENTION_DAYS=30
SUCCESS_RETENTION_DAYS=14
FAILED_RETENTION_DAYS=90

ALLOW_PRIVATE_DESTINATIONS=false
ALLOW_LOCALHOST_DESTINATIONS=false

# Optional first administrator. Leave blank to use the web setup.
ADMIN_NAME=Admin
ADMIN_EMAIL=
ADMIN_PASSWORD=

# Optional machine-to-machine API token.
API_TOKEN=
```

For production, change at least `POSTGRES_PASSWORD` and set `APP_BASE_URL` to the externally reachable HTTPS URL.

Create `compose.yaml`:

```yaml
services:
  db:
    image: postgres:17-alpine
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-zentwhook}
      POSTGRES_USER: ${POSTGRES_USER:-zentwhook}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env}
    volumes:
      - zentwhook_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-zentwhook} -d ${POSTGRES_DB:-zentwhook}"]
      interval: 5s
      timeout: 5s
      retries: 20
    restart: unless-stopped

  app:
    image: ghcr.io/zentworks/zentwhook:latest
    environment:
      DATABASE_URL: postgresql+psycopg://${POSTGRES_USER:-zentwhook}:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB:-zentwhook}
      APP_BASE_URL: ${APP_BASE_URL:-http://localhost:8080}
      DEFAULT_LANGUAGE: ${DEFAULT_LANGUAGE:-de}
      LOG_LEVEL: ${LOG_LEVEL:-info}
      EVENT_RETENTION_DAYS: ${EVENT_RETENTION_DAYS:-30}
      SUCCESS_RETENTION_DAYS: ${SUCCESS_RETENTION_DAYS:-14}
      FAILED_RETENTION_DAYS: ${FAILED_RETENTION_DAYS:-90}
      ALLOW_PRIVATE_DESTINATIONS: ${ALLOW_PRIVATE_DESTINATIONS:-false}
      ALLOW_LOCALHOST_DESTINATIONS: ${ALLOW_LOCALHOST_DESTINATIONS:-false}
      ADMIN_NAME: ${ADMIN_NAME:-Admin}
      ADMIN_EMAIL: ${ADMIN_EMAIL:-}
      ADMIN_PASSWORD: ${ADMIN_PASSWORD:-}
      API_TOKEN: ${API_TOKEN:-}
    volumes:
      - zentwhook_data:/data
    ports:
      - "${HTTP_PORT:-8080}:8080"
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

  worker:
    image: ghcr.io/zentworks/zentwhook:latest
    command: ["./scripts/start-worker.sh"]
    environment:
      DATABASE_URL: postgresql+psycopg://${POSTGRES_USER:-zentwhook}:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB:-zentwhook}
      DEFAULT_LANGUAGE: ${DEFAULT_LANGUAGE:-de}
      LOG_LEVEL: ${LOG_LEVEL:-info}
      EVENT_RETENTION_DAYS: ${EVENT_RETENTION_DAYS:-30}
      SUCCESS_RETENTION_DAYS: ${SUCCESS_RETENTION_DAYS:-14}
      FAILED_RETENTION_DAYS: ${FAILED_RETENTION_DAYS:-90}
      ALLOW_PRIVATE_DESTINATIONS: ${ALLOW_PRIVATE_DESTINATIONS:-false}
      ALLOW_LOCALHOST_DESTINATIONS: ${ALLOW_LOCALHOST_DESTINATIONS:-false}
    volumes:
      - zentwhook_data:/data
    depends_on:
      db:
        condition: service_healthy
      app:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "python", "-m", "zentwhook.worker_health"]
      interval: 15s
      timeout: 5s
      start_period: 20s
      retries: 3
    restart: unless-stopped

volumes:
  zentwhook_db:
  zentwhook_data:
```

Start ZentWHook:

```bash
docker compose up -d
```

Open:

```text
http://YOUR-DOCKER-HOST:8080
```

On the first start, ZentWHook shows a short administrator setup unless `ADMIN_EMAIL` and `ADMIN_PASSWORD` were configured.

Check status:

```bash
docker compose ps
docker compose logs -f app worker
```

## 2. Docker CLI

Docker Compose is recommended because ZentWHook consists of PostgreSQL, the web application and a worker. The same stack can also be started directly with Docker.

Create the network and persistent volumes:

```bash
docker network create zentwhook
docker volume create zentwhook_db
docker volume create zentwhook_data
```

Start PostgreSQL. Replace the example password in both the database and application commands:

```bash
docker run -d \
  --name zentwhook-db \
  --network zentwhook \
  --restart unless-stopped \
  -e POSTGRES_DB=zentwhook \
  -e POSTGRES_USER=zentwhook \
  -e POSTGRES_PASSWORD='replace-with-a-strong-password' \
  -v zentwhook_db:/var/lib/postgresql/data \
  postgres:17-alpine
```

Wait until PostgreSQL is ready:

```bash
until docker exec zentwhook-db pg_isready -U zentwhook -d zentwhook >/dev/null 2>&1; do sleep 2; done
```

Start the web application:

```bash
docker run -d \
  --name zentwhook-app \
  --network zentwhook \
  --restart unless-stopped \
  -p 8080:8080 \
  -e DATABASE_URL='postgresql+psycopg://zentwhook:replace-with-a-strong-password@zentwhook-db:5432/zentwhook' \
  -e APP_BASE_URL='http://localhost:8080' \
  -e DEFAULT_LANGUAGE=de \
  -v zentwhook_data:/data \
  ghcr.io/zentworks/zentwhook:latest
```

Start the worker:

```bash
docker run -d \
  --name zentwhook-worker \
  --network zentwhook \
  --restart unless-stopped \
  -e DATABASE_URL='postgresql+psycopg://zentwhook:replace-with-a-strong-password@zentwhook-db:5432/zentwhook' \
  -e DEFAULT_LANGUAGE=de \
  -v zentwhook_data:/data \
  ghcr.io/zentworks/zentwhook:latest \
  ./scripts/start-worker.sh
```

# First flow

1. Create an **Incoming Webhook**.
2. Copy its `/in/<slug>` URL into the service that should send the webhook.
3. Send a test event and inspect the captured request.
4. Add a **Direct** flow and paste the real destination URL for simple 1:1 forwarding.
5. Only switch to a custom request body when fields need to be mapped or transformed.
6. Use **If / Else** when routing depends on incoming values.
7. Use Dry Run before enabling a complex route.

# Environment variables

The public repository contains `.env.example`.

| Variable | Default / Example | Required | Description |
|---|---|---:|---|
| `HTTP_PORT` | `8080` | No | Published host port in the Compose example. |
| `APP_BASE_URL` | `http://localhost:8080` | **Production: yes** | Externally reachable base URL. Use HTTPS in production. |
| `DEFAULT_LANGUAGE` | `de` | No | Server-side UI language: `de` or `en`. |
| `LOG_LEVEL` | `info` | No | Application log level. |
| `POSTGRES_DB` | `zentwhook` | No | PostgreSQL database name. |
| `POSTGRES_USER` | `zentwhook` | No | PostgreSQL user. |
| `POSTGRES_PASSWORD` | — | **Yes** | PostgreSQL password. Use a strong unique value. |
| `EVENT_RETENTION_DAYS` | `30` | No | Generic event retention fallback. |
| `SUCCESS_RETENTION_DAYS` | `14` | No | Default retention for successful events. |
| `FAILED_RETENTION_DAYS` | `90` | No | Default retention for failed events. |
| `ALLOW_PRIVATE_DESTINATIONS` | `false` | No | Global opt-in for RFC1918/private destination addresses. |
| `ALLOW_LOCALHOST_DESTINATIONS` | `false` | No | Global opt-in for loopback destinations. |
| `ADMIN_NAME` | `Admin` | No | Initial administrator display name. |
| `ADMIN_EMAIL` | empty | No | Optional first administrator e-mail. |
| `ADMIN_PASSWORD` | empty | No | Optional first administrator password. |
| `API_TOKEN` | empty | No | Optional machine-to-machine API token sent as `X-ZentWHook-Token`. |

Encryption and session keys are created in `/data` on first start. Do not delete `encryption.key` while encrypted records still exist.

# Reverse proxy

Use a reverse proxy such as NGINX, Traefik, Caddy or ZentProxy to terminate TLS and expose ZentWHook over HTTPS.

Set:

```dotenv
APP_BASE_URL=https://hooks.example.com
```

Then configure the actual reverse proxy CIDR under **Settings → Trusted Proxies** before trusting forwarded client-IP headers.

Example NGINX location:

```nginx
location / {
    proxy_pass http://zentwhook-app:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_http_version 1.1;
}
```

# API

ZentWHook exposes its versioned REST API under:

```text
/api/v1/
```

Local API documentation:

```text
/api/docs
```

OpenAPI document:

```text
/api/v1/openapi.json
```

Health endpoints:

```text
/health
/ready
```

For machine access, configure `API_TOKEN` and send it as:

```text
X-ZentWHook-Token: <token>
```

# Updating

## Docker Compose

Pull the current application image and recreate the services:

```bash
docker compose pull
docker compose up -d
```

The app container runs Alembic migrations before accepting HTTP traffic. Named volumes are not replaced by image updates.

Before important upgrades, back up PostgreSQL and the application data volume.

## Docker CLI

Pull the new image:

```bash
docker pull ghcr.io/zentworks/zentwhook:latest
```

Recreate `zentwhook-app` and `zentwhook-worker` with the same environment, network and volume mappings. Do not remove the PostgreSQL or application-data volumes.

# Backup and restore

Back up all three items:

1. PostgreSQL database
2. `zentwhook_data`, especially `/data/encryption.key`
3. deployment `.env`

Database example:

```bash
docker compose exec -T db \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc \
  > zentwhook-db.dump
```

The repository also contains `docs/BACKUP.md` and `docs/UPGRADE.md` with additional operational details.

# Security

ZentWHook accepts untrusted inbound requests and can perform outbound HTTP requests, so deployment security matters.

- Endpoint and destination secrets are encrypted at rest.
- Event bodies, query strings and stored header values are encrypted where applicable.
- Secrets are never returned in clear text after storage.
- Sensitive headers and configured payload fields are masked in the UI.
- Browser mutations use CSRF protection.
- Sessions are HttpOnly/SameSite and become Secure when `APP_BASE_URL` uses HTTPS.
- Private, loopback, link-local and metadata-style outbound targets are blocked by default.
- Outbound redirects are disabled.
- DNS is re-resolved immediately before delivery.
- Private/internal targets can be enabled deliberately for self-hosted environments.

For higher-risk installations, also enforce network-level egress restrictions and reverse-proxy rate limiting.

See [SECURITY.md](SECURITY.md).

# Persistent data

| Data | Location |
|---|---|
| PostgreSQL | `zentwhook_db` volume |
| Encryption/session keys | `zentwhook_data` volume (`/data`) |
| Deployment configuration | `.env` on the Docker host |

Container updates must not replace these volumes.

# Development

The production image uses Python 3.13. For a local source checkout:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=sqlite:///./dev.sqlite3
export DATA_DIR=./.zentwhook-data
python -m zentwhook.bootstrap
alembic upgrade head
uvicorn zentwhook.main:app --reload --port 8080
```

The production deployment uses PostgreSQL. SQLite is intended for development and tests only.

# License

MIT — see [LICENSE](LICENSE).
