import secrets, time
from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import RedirectResponse
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import User
from ..security import hash_password,verify_password,sign_session,read_session,require_csrf
from ..config import settings
from ..i18n import t
router=APIRouter()
_attempts={}

def render(request,name,ctx=None,status=200):
    lang=getattr(request.state,'lang',settings.default_language)
    c={'request':request,'lang':lang,'_':lambda key:t(lang,key),**(ctx or {})};return request.app.state.templates.TemplateResponse(request,name,c,status_code=status)

@router.get('/setup')
def setup_page(request:Request,db:Session=Depends(get_db)):
    if db.scalar(select(func.count(User.id)))>0:return RedirectResponse('/login',303)
    return render(request,'setup.html')

@router.post('/setup')
def setup(request:Request,name:str=Form(...),email:str=Form(...),password:str=Form(...),language:str=Form('de'),db:Session=Depends(get_db)):
    if db.scalar(select(func.count(User.id)))>0:return RedirectResponse('/login',303)
    if len(password)<10:return render(request,'setup.html',{'error':'Passwort muss mindestens 10 Zeichen haben.'},400)
    u=User(name=name.strip(),email=email.strip().lower(),password_hash=hash_password(password),language=language if language in ('de','en') else 'de',role='admin');db.add(u);db.commit();db.refresh(u)
    csrf=secrets.token_urlsafe(24);resp=RedirectResponse('/dashboard',303);resp.set_cookie('zentwhook_session',sign_session(u.id,csrf,u.session_version),httponly=True,samesite='lax',secure=settings.cookie_secure,max_age=43200);return resp

@router.get('/login')
def login_page(request:Request,db:Session=Depends(get_db)):
    if db.scalar(select(func.count(User.id)))==0:return RedirectResponse('/setup',303)
    return render(request,'login.html')

@router.post('/login')
def login(request:Request,email:str=Form(...),password:str=Form(...),db:Session=Depends(get_db)):
    ip=request.client.host if request.client else 'unknown';now=time.time();a=_attempts.get(ip,[]);a=[x for x in a if now-x<300]
    if len(a)>=10:return render(request,'login.html',{'error':'Zu viele Anmeldeversuche. Bitte später erneut versuchen.'},429)
    u=db.scalar(select(User).where(User.email==email.strip().lower()))
    if not u or not verify_password(password,u.password_hash):
        a.append(now);_attempts[ip]=a;return render(request,'login.html',{'error':'Ungültige Zugangsdaten.'},401)
    _attempts.pop(ip,None);csrf=secrets.token_urlsafe(24);resp=RedirectResponse('/dashboard',303);resp.set_cookie('zentwhook_session',sign_session(u.id,csrf,u.session_version),httponly=True,samesite='lax',secure=settings.cookie_secure,max_age=43200);return resp

@router.post('/logout')
async def logout(request:Request):
    form=await request.form();request.state.form_csrf=form.get('_csrf');require_csrf(request)
    r=RedirectResponse('/login',303);r.delete_cookie('zentwhook_session');return r

@router.post('/language/{lang}')
async def language(lang:str,request:Request,db:Session=Depends(get_db)):
    form=await request.form();request.state.form_csrf=form.get('_csrf');require_csrf(request)
    if lang not in ('de','en'):lang='de'
    sess=read_session(request.cookies.get('zentwhook_session'))
    if sess:
        u=db.get(User,sess['user_id'])
        if u and int(sess.get('session_version',1))==int(getattr(u,'session_version',1) or 1):u.language=lang;db.commit()
    r=RedirectResponse(request.headers.get('referer','/dashboard'),303);r.set_cookie('zentwhook_lang',lang,samesite='lax',secure=settings.cookie_secure);return r
