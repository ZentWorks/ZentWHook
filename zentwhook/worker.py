import logging, os, time
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from .db import SessionLocal
from .models import Job, Delivery, Setting
from .services import process_event, perform_delivery, retention_cleanup
from .config import settings
logging.basicConfig(level=getattr(logging,settings.log_level.upper(),logging.INFO),format='%(asctime)s %(levelname)s %(name)s %(message)s')
for noisy_logger in ('httpx','httpcore'):
    logging.getLogger(noisy_logger).setLevel(logging.WARNING)
log=logging.getLogger('zentwhook.worker')

def claim(db):
    stmt=select(Job).where(Job.status=='queued',Job.run_at<=datetime.now(timezone.utc)).order_by(Job.run_at,Job.id).with_for_update(skip_locked=True).limit(1)
    job=db.scalar(stmt)
    if job:
        job.status='running';job.locked_at=datetime.now(timezone.utc);job.attempts+=1;db.commit();db.refresh(job)
    return job

def run_job(db,job):
    if job.kind=='process_event': process_event(db,int(job.payload['event_id']))
    elif job.kind=='retry_delivery':
        d=db.scalar(select(Delivery).where(Delivery.id==int(job.payload['delivery_id'])).with_for_update())
        if d and d.status in ('retrying','queued','failed'): perform_delivery(db,d)
    elif job.kind=='retention_cleanup': retention_cleanup(db)

def main():
    log.debug('ZentWHook worker started')
    with SessionLocal() as db:
        stale=db.scalars(select(Job).where(Job.status=='running',Job.locked_at < datetime.now(timezone.utc)-timedelta(minutes=5))).all()
        for j in stale:j.status='queued';j.locked_at=None
        db.commit()
    last_cleanup=0;last_heartbeat=0;last_recover=0
    while True:
        with SessionLocal() as db:
            if time.time()-last_heartbeat>5:
                hb=db.get(Setting,'worker_heartbeat')
                value=datetime.now(timezone.utc).isoformat()
                if hb:hb.value_json=value
                else:db.add(Setting(key='worker_heartbeat',value_json=value))
                db.commit();last_heartbeat=time.time()
            if time.time()-last_recover>60:
                stale=db.scalars(select(Job).where(Job.status=='running',Job.locked_at < datetime.now(timezone.utc)-timedelta(minutes=5))).all()
                for j in stale:j.status='queued';j.locked_at=None
                db.commit();last_recover=time.time()
            if time.time()-last_cleanup>3600:
                try: retention_cleanup(db)
                except Exception: log.exception('retention cleanup failed')
                last_cleanup=time.time()
            job=claim(db)
            if not job:
                time.sleep(0.5);continue
            try:
                run_job(db,job);job.status='done';job.last_error='';db.commit()
            except Exception as e:
                log.exception('job failed kind=%s id=%s',job.kind,job.id);job.last_error=str(e);job.status='failed' if job.attempts>=5 else 'queued';job.run_at=datetime.now(timezone.utc)+timedelta(seconds=min(60,5*job.attempts));db.commit()
        time.sleep(0.05)
if __name__=='__main__': main()
