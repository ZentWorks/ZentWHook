# Backup and restore

## What to back up

- PostgreSQL database (`zentwhook_db`)
- application data volume (`zentwhook_data`), especially `encryption.key`
- `.env`

## Database backup

```bash
docker compose exec -T db \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc \
  > zentwhook-db.dump
```

If the variables are not exported in your shell, use the values from `.env` explicitly.

## Data-volume backup

```bash
docker run --rm \
  -v zentwhook_zentwhook_data:/data:ro \
  -v "$PWD":/backup \
  alpine sh -c 'tar czf /backup/zentwhook-data.tar.gz -C /data .'
```

The actual Compose volume prefix can differ. Check `docker volume ls`.

## Restore

1. Stop app and worker: `docker compose stop app worker`.
2. Restore `zentwhook_data` before starting the application.
3. Restore the PostgreSQL dump into the target database.
4. Start: `docker compose up -d`.
5. Confirm `/ready` reports database, queue and worker as healthy.

Never restore an encrypted database without the matching `encryption.key`.
