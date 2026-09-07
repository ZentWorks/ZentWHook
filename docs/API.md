# REST API

Base path: `/api/v1/`

The authoritative specification is served at `/api/v1/openapi.json`. A local, CDN-free human-readable endpoint list is available at `/api/docs`. A generated snapshot is also included as `docs/openapi.json` in release archives.

## Authentication

For service clients, configure `API_TOKEN` and send:

```text
X-ZentWHook-Token: <token>
```

A logged-in browser session can also read API endpoints. Browser-session writes require `X-CSRF-Token`. Machine-token requests do not use CSRF because they do not rely on cookies.

Secrets are write-only. Endpoint and destination API responses only expose whether a secret is configured, never the secret value itself.

## Resources

- `GET /api/v1/status`
- Endpoint CRUD: `GET/POST /api/v1/endpoints`, `GET/PUT/DELETE /api/v1/endpoints/{id}`
- Events: `GET /api/v1/events`, `GET /api/v1/events/{id}`
- Replay: `POST /api/v1/events/{id}/replay`
- Dry Run: `POST /api/v1/events/{id}/dry-run`
- Destination CRUD: `GET/POST /api/v1/destinations`, `GET/PUT/DELETE /api/v1/destinations/{id}`
- Flow CRUD: `GET/POST /api/v1/flows`, `GET/PUT/DELETE /api/v1/flows/{id}`
- Deliveries: `GET /api/v1/deliveries`, `GET /api/v1/deliveries/{id}`
- Retry: `POST /api/v1/deliveries/{id}/retry`

## Incoming webhook URL

Dynamic webhook receivers live outside the management API:

```text
/in/<endpoint-slug>
```

The accepted HTTP methods, authentication, source-IP rules, Content-Types and payload limits are configured per Incoming Endpoint. Because each endpoint can expose a different method/security contract, `/in/{slug}` is intentionally not part of the generic management OpenAPI document.

## Webhook-scoped targets (0.2.0)

Destinations are no longer global configuration objects in the product model. `POST`/`PUT /api/v1/destinations` require `endpoint_id`. Flow routes may only reference destinations owned by the same endpoint. `FlowIn.mode` is `direct` or `conditional`; each route may contain its own `mappings` array.

## Destination request mode (0.3.0)

Destination create/update payloads accept `request_mode`:

- `passthrough` (default): forward the incoming method/body/query/safe headers.
- `custom`: use configured method/query/headers and route mappings.

`GET /api/v1/destinations/{id}` returns the current `request_mode`.
