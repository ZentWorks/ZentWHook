#!/bin/sh
set -eu
python -m zentwhook.bootstrap
python -m zentwhook.wait_db
exec python -m zentwhook.worker
