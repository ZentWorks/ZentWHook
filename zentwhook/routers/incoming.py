import asyncio, json, logging, time
from collections import defaultdict, deque
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import IncomingEndpoint,Setting
from ..security import client_ip,ip_in_any
from ..incoming_auth import check_endpoint_auth
from ..services import create_event,queue_job,process_event
from ..validation import content_type_allowed
router=APIRouter()
log=logging.getLogger('zentwhook.incoming')
_hits=defaultdict(deque)
_last_hit_cleanup=0.0

def rate_ok(ep,ip):
    global _last_hit_cleanup
    n=max(1,ep.rate_limit_per_minute);q=_hits[(ep.id,ip)];now=time.monotonic()
    if now-_last_hit_cleanup>60:
        for key,dq in list(_hits.items()):
            while dq and now-dq[0]>60:dq.popleft()
            if not dq:_hits.pop(key,None)
        _last_hit_cleanup=now
    while q and now-q[0]>60:q.popleft()
    if len(q)>=n:return False
    q.append(now);return True

@router.api_route('/in/{slug}',methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'],include_in_schema=False)
async def receive(slug:str,request:Request,db:Session=Depends(get_db)):
    ep=db.scalar(select(IncomingEndpoint).where(IncomingEndpoint.slug==slug))
    if not ep or not ep.active:raise HTTPException(404,'Endpoint not found')
    if request.method not in (ep.methods or []):raise HTTPException(405,'Method not allowed')
    trusted=(db.get(Setting,'trusted_proxies').value_json if db.get(Setting,'trusted_proxies') else []) or []
    ip=client_ip(request,trusted)
    if ep.ip_denylist and ip_in_any(ip,ep.ip_denylist):raise HTTPException(403,'Source IP denied')
    if ep.ip_allowlist and not ip_in_any(ip,ep.ip_allowlist):raise HTTPException(403,'Source IP not allowed')
    if not rate_ok(ep,ip):raise HTTPException(429,'Rate limit exceeded')
    cl=request.headers.get('content-length')
    if cl:
        try:
            if int(cl)>ep.max_payload_bytes:raise HTTPException(413,'Payload too large')
        except ValueError:raise HTTPException(400,'Invalid Content-Length')
    try:body=await asyncio.wait_for(request.body(),timeout=ep.request_timeout_seconds)
    except TimeoutError:raise HTTPException(408,'Request timeout')
    if len(body)>ep.max_payload_bytes:raise HTTPException(413,'Payload too large')
    raw_ct=request.headers.get('content-type','')
    # Empty requests (for example GET/HEAD probes) do not need a Content-Type.
    # Requests with a body are matched against exact MIME types and supported wildcards.
    if body and ep.content_types and not content_type_allowed(raw_ct,ep.content_types):
        raise HTTPException(415,'Content-Type not allowed')
    query={}
    for key,value in request.query_params.multi_items():
        if key not in query: query[key]=value
        elif isinstance(query[key],list): query[key].append(value)
        else: query[key]=[query[key],value]
    ok,msg=check_endpoint_auth(ep,dict(request.headers),body)
    if not ok:
        ev=create_event(db,ep,request.method,ip,request.headers.get('content-type',''),body,dict(request.headers),query,False,msg);ev.status='rejected';db.commit();raise HTTPException(401,detail={'message':msg,'request_id':ev.request_id})
    ev=create_event(db,ep,request.method,ip,request.headers.get('content-type',''),body,dict(request.headers),query,ok,msg)
    log.debug('request accepted request_id=%s endpoint=%s source_ip=%s',ev.request_id,ep.name,ip,extra={'request_id':ev.request_id})
    if ep.synchronous:
        process_event(db,ev.id);db.refresh(ev);return JSONResponse({'accepted':True,'request_id':ev.request_id,'status':ev.status},200)
    queue_job(db,'process_event',{'event_id':ev.id});return JSONResponse({'accepted':True,'request_id':ev.request_id},202)
