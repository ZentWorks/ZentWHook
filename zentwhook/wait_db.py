import time
from sqlalchemy import text
from .db import engine
for i in range(60):
    try:
        with engine.connect() as c: c.execute(text('select count(*) from jobs'))
        raise SystemExit(0)
    except Exception:
        time.sleep(1)
raise SystemExit('database unavailable')
