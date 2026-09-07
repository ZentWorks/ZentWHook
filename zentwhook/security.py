from __future__ import annotations
import base64, hashlib, hmac, ipaddress, json, secrets, time
from cryptography.fernet import Fernet
from fastapi import Request, HTTPException
from .config import data_path, settings

SENSITIVE={'authorization','proxy_authorization','cookie','set_cookie','x_api_key','x_auth_token','password','token','access_token','secret','api_key'}

def _read_key(name):
    p=data_path(name)
    if not p.exists():
        from .bootstrap import ensure; ensure(name)
    return p.read_text().strip().encode()

def fernet(): return Fernet(_read_key('encryption.key'))
def encrypt(value:str)->str:
    if not value: return ''
    return fernet().encrypt(value.encode()).decode()
def decrypt(value:str)->str:
    if not value: return ''
    return fernet().decrypt(value.encode()).decode()

def hash_password(password:str)->str:
    salt=secrets.token_bytes(16); n=2**15; r=8; p=1
    digest=hashlib.scrypt(password.encode(),salt=salt,n=n,r=r,p=p,dklen=32,maxmem=64*1024*1024)
    return f'scrypt${n}${r}${p}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}'
def verify_password(password, encoded):
    try:
        _,ns,rs,ps,salt,dig=encoded.split('$'); salt=base64.urlsafe_b64decode(salt); expected=base64.urlsafe_b64decode(dig)
        actual=hashlib.scrypt(password.encode(),salt=salt,n=int(ns),r=int(rs),p=int(ps),dklen=len(expected),maxmem=64*1024*1024)
        return hmac.compare_digest(actual,expected)
    except Exception: return False

def sign_session(user_id:int, csrf:str, ttl=43200):
    payload=f'{user_id}:{int(time.time())+ttl}:{csrf}'
    sig=hmac.new(_read_key('session.key'),payload.encode(),hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f'{payload}:{sig}'.encode()).decode()
def read_session(token:str|None):
    if not token:return None
    try:
        raw=base64.urlsafe_b64decode(token).decode(); uid,exp,csrf,sig=raw.split(':',3); payload=f'{uid}:{exp}:{csrf}'
        good=hmac.new(_read_key('session.key'),payload.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig,good) or int(exp)<time.time(): return None
        return {'user_id':int(uid),'csrf':csrf}
    except Exception:return None

def require_csrf(request:Request):
    sess=read_session(request.cookies.get('zentwhook_session'))
    if not sess: raise HTTPException(401,'Login required')
    token=request.headers.get('x-csrf-token')
    if not token: token=getattr(request.state,'form_csrf',None)
    if not token or not hmac.compare_digest(str(token),str(sess['csrf'])): raise HTTPException(403,'CSRF validation failed')

def mask_value(name:str,value):
    lname=name.lower().replace('-','_')
    return '********' if lname in SENSITIVE or any(x in lname for x in ['password','secret','token','api_key']) else value

def mask_json(value, custom:list[str]|None=None):
    custom={x.lower() for x in (custom or [])}
    if isinstance(value,dict):
        return {k:('********' if k.lower() in custom or mask_value(k,'x')=='********' else mask_json(v,custom)) for k,v in value.items()}
    if isinstance(value,list): return [mask_json(v,custom) for v in value]
    return value

def ip_in_any(ip, cidrs):
    try:
        addr=ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(c,strict=False) for c in cidrs)
    except ValueError: return False

def client_ip(request:Request,trusted_proxies:list[str]):
    remote=request.client.host if request.client else ''
    if trusted_proxies and ip_in_any(remote,trusted_proxies):
        cf=request.headers.get('cf-connecting-ip','').strip()
        if cf:
            try: ipaddress.ip_address(cf); return cf
            except ValueError: pass
        xff=request.headers.get('x-forwarded-for','').split(',')[0].strip()
        if xff:
            try: ipaddress.ip_address(xff); return xff
            except ValueError: pass
    return remote
