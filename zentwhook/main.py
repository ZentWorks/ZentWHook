from __future__ import annotations
import logging
from pathlib import Path
from fastapi import FastAPI, Request
from contextlib import asynccontextmanager
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, text
from .config import settings
from .db import SessionLocal
from .models import User, Job, Setting
from .security import hash_password, read_session
from .i18n import t
from .routers import auth,incoming,web,api
from . import __version__

logging.basicConfig(level=getattr(logging,settings.log_level.upper(),logging.INFO),format='%(asctime)s %(levelname)s %(name)s request_id=%(request_id)s %(message)s')
for noisy_logger in ('httpx','httpcore'):
    logging.getLogger(noisy_logger).setLevel(logging.WARNING)
class RequestIdFilter(logging.Filter):
    def filter(self,record):
        if not hasattr(record,'request_id'):record.request_id='-'
        return True
for h in logging.getLogger().handlers:h.addFilter(RequestIdFilter())

BASE=Path(__file__).parent
@asynccontextmanager
async def lifespan(app:FastAPI):
    if settings.admin_email and settings.admin_password:
        with SessionLocal() as db:
            if (db.scalar(select(func.count(User.id))) or 0)==0:
                db.add(User(name=settings.admin_name,email=settings.admin_email.lower(),password_hash=hash_password(settings.admin_password),language=settings.default_language,role='admin'));db.commit()
    yield
app=FastAPI(title='ZentWHook',version=__version__,docs_url=None,redoc_url=None,openapi_url='/api/v1/openapi.json',lifespan=lifespan)
templates=Jinja2Templates(directory=str(BASE/'templates'))
app.state.templates=templates
templates.env.globals['_']=lambda key:key
app.mount('/static',StaticFiles(directory=str(BASE/'static')),name='static')

@app.middleware('http')
async def common(request:Request,call_next):
    lang=request.cookies.get('zentwhook_lang',settings.default_language)
    sess=read_session(request.cookies.get('zentwhook_session'))
    request.state.session_revoked=False
    if sess:
        with SessionLocal() as db:
            u=db.get(User,sess['user_id'])
            if u and int(sess.get('session_version',1))==int(getattr(u,'session_version',1) or 1):lang=u.language or lang
            else:request.state.session_revoked=True
    request.state.lang=lang if lang in ('de','en') else 'de'
    resp=await call_next(request)
    resp.headers['X-Content-Type-Options']='nosniff';resp.headers['X-Frame-Options']='DENY';resp.headers['Referrer-Policy']='same-origin';resp.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()';resp.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    return resp

@app.get('/health',include_in_schema=False)
def health():return {'status':'ok','version':__version__}
@app.get('/ready',include_in_schema=False)
def ready():
    try:
        from datetime import datetime,timezone
        with SessionLocal() as db:
            db.execute(text('select 1'));q=db.scalar(select(func.count(Job.id)).where(Job.status=='queued')) or 0;hb=db.get(Setting,'worker_heartbeat')
        worker='missing'
        if hb and hb.value_json:
            try:
                age=(datetime.now(timezone.utc)-datetime.fromisoformat(str(hb.value_json))).total_seconds();worker='ok' if age<20 else 'stale'
            except Exception:worker='invalid'
        body={'status':'ready' if worker=='ok' else 'not_ready','database':'ok','queue':'ok','worker':worker,'queued_jobs':q}
        return body if worker=='ok' else JSONResponse(body,503)
    except Exception:return JSONResponse({'status':'not_ready','database':'error','worker':'unknown'},503)

app.include_router(auth.router)
app.include_router(incoming.router)
app.include_router(web.router)
app.include_router(api.router)
