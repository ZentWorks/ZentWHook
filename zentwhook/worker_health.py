from datetime import datetime,timezone
from .db import SessionLocal
from .models import Setting

def main():
    try:
        with SessionLocal() as db:hb=db.get(Setting,'worker_heartbeat')
        if not hb or not hb.value_json:raise SystemExit(1)
        age=(datetime.now(timezone.utc)-datetime.fromisoformat(str(hb.value_json))).total_seconds()
        raise SystemExit(0 if age<20 else 1)
    except Exception:raise SystemExit(1)
if __name__=='__main__':main()
