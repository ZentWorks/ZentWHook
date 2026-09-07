# Upgrade notes

ZentWHook uses semantic versioning and Alembic schema migrations.

## Normal upgrade

1. Back up PostgreSQL and `zentwhook_data`.
2. Pull/build the new image.
3. Run `docker compose up -d`.
4. The app container runs `alembic upgrade head` before accepting HTTP traffic.
5. The worker waits until the app container is healthy and the schema is available.
6. Check `/ready` and the worker health status.

## Rollback

Application rollback and database rollback are separate operations. Do not run `alembic downgrade` in production unless the release notes explicitly declare that downgrade safe. Restore a pre-upgrade database backup for destructive/incompatible rollback scenarios.

Image updates do not overwrite named volumes.

## 0.1.x → 0.2.0

Version 0.2.0 changes the configuration ownership model. Flows remain attached to their Incoming Webhook and destinations are now webhook-scoped. During migration, a legacy destination referenced by flows from multiple webhooks is cloned per webhook and each route is repointed to its own copy. Existing flow-level mappings remain valid; new route-specific mappings take precedence when configured.

Back up PostgreSQL and `/data/encryption.key` before upgrading. The app runs the Alembic migration automatically on startup.

## 0.2.x → 0.3.0

Version 0.3.0 introduces the simplified destination model. New destinations default to `request_mode=passthrough`, which forwards the original incoming HTTP method, raw stored body, query parameters and safe request headers. Existing destinations are migrated to `request_mode=custom` so their previous configured method/header/query/mapping behavior does not change.

No manual data migration is required. The app container runs the Alembic migration automatically. Back up PostgreSQL and `/data/encryption.key` before upgrading as usual.

Passthrough deliberately strips hop-by-hop headers, `Host`, `Content-Length`, incoming `Authorization`, cookies and common incoming API-key headers. Configure destination authentication or additional destination headers explicitly when the upstream target requires them.
