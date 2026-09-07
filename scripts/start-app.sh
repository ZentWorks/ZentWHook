#!/bin/sh
set -eu
python -m zentwhook.bootstrap
alembic upgrade head
exec uvicorn zentwhook.main:app --host 0.0.0.0 --port 8080 --no-proxy-headers --no-access-log --log-level warning
