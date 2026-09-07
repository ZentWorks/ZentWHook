from __future__ import annotations
import json, re, secrets
from urllib.parse import urlparse, urlencode
from pathlib import Path
from fastapi import APIRouter, Request, Depends, Form, UploadFile, File, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, Response
from sqlalchemy import select, func, desc, or_
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import User, IncomingEndpoint, EndpointAuth, Event, Destination, Flow, FlowRule, Mapping, FlowDestination, RouteMapping, Delivery, DeliveryAttempt, Setting, Job
from ..deps import require_user
from ..security import encrypt, decrypt, read_session, require_csrf, mask_json, hash_password, verify_password, sign_session
from ..services import get_setting,set_setting,simulate_event,clone_event,manual_retry,raw_headers,queue_job,event_context,event_payload
from ..engine import parse_json, flatten_paths
from ..ssrf import validate_destination_url, SSRFError
from ..config import settings
from .. import __version__
from ..validation import validate_cidrs,validate_header_name,validate_headers,validate_mapping_path,validate_methods,validate_content_types,validate_rule_operator
from ..incoming_auth import validate_hmac_template

router=APIRouter()


def ctx(request, db, **extra):
    user=require_user(request,db)
    sess=read_session(request.cookies.get('zentwhook_session'))
    lang=user.language or settings.default_language
    from ..i18n import t
    path=request.url.path
    if path.startswith(('/endpoints','/flows','/destinations')):nav_section='webhooks'
    elif path.startswith(('/events','/deliveries')):nav_section='events'
    elif path.startswith(('/settings','/api/docs')):nav_section='settings'
    else:nav_section='dashboard'
    return {'request':request,'user':user,'csrf':sess['csrf'],'lang':lang,'_':lambda key:t(lang,key),'version':__version__,'nav_section':nav_section,**extra}

def render(request,db,name,**extra):
    return request.app.state.templates.TemplateResponse(request,name,ctx(request,db,**extra))

def render_fragment(request,db,name,**extra):
    context=ctx(request,db,**extra)
    html=request.app.state.templates.env.get_template(name).render(context)
    return Response(html,media_type='text/html')

def safe_event_return_to(value:str|None, endpoint_id:int):
    value=(value or '').strip()
    if value.startswith('/events') and not value.startswith('//'):
        return value
    if value in (f'/endpoints/{endpoint_id}', f'/endpoints/{endpoint_id}/'):
        return f'/endpoints/{endpoint_id}'
    if value in ('/dashboard','/dashboard/'):
        return '/dashboard'
    return f'/endpoints/{endpoint_id}'

async def form_with_csrf(request):
    form=await request.form();request.state.form_csrf=form.get('_csrf');require_csrf(request);return form

def parse_lines(text): return [x.strip() for x in (text or '').replace(',','\n').splitlines() if x.strip()]
def parse_kv(text):
    out={}
    for line in (text or '').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        if ':' in line:k,v=line.split(':',1);out[k.strip()]=v.strip()
        elif '=' in line:k,v=line.split('=',1);out[k.strip()]=v.strip()
    return out

def safe_slug(s):
    s=re.sub(r'[^a-zA-Z0-9_-]+','-',s.strip()).strip('-_').lower()
    return s[:120] or secrets.token_hex(4)

def form_int(form,key,default,minimum=None,maximum=None):
    try:value=int(form.get(key) if form.get(key) not in (None,'') else default)
    except (TypeError,ValueError):raise HTTPException(400,f'Ungültiger Zahlenwert: {key}')
    if minimum is not None and value<minimum:raise HTTPException(400,f'{key} ist zu klein')
    if maximum is not None and value>maximum:raise HTTPException(400,f'{key} ist zu groß')
    return value

def jsonish(s):
    if s is None or s=='':return None
    try:return json.loads(s)
    except:return s

def destination_name_from_url(url):
    try:
        host=(urlparse(url).hostname or '').lower()
    except Exception: host=''
    if 'discord.com' in host or 'discordapp.com' in host:return 'Discord'
    if 'hooks.slack.com' in host:return 'Slack'
    if host:
        clean=host[4:] if host.startswith('www.') else host
        return clean.split('.')[0].replace('-',' ').title() or 'Ziel'
    return 'Ziel'



def sample_data_for_endpoint(db:Session, endpoint_id:int, sample_event_id:int|None=None):
    stmt=select(Event).where(Event.endpoint_id==endpoint_id)
    if sample_event_id:
        stmt=stmt.where(Event.id==sample_event_id)
    ev=db.scalar(stmt.order_by(Event.received_at.desc()).limit(1))
    paths=[]
    if ev:
        parsed=event_context(ev)
        paths=flatten_paths(parsed)
    events=db.scalars(select(Event).where(Event.endpoint_id==endpoint_id).order_by(Event.received_at.desc()).limit(30)).all()
    return ev, paths, events

def clone_destination(db:Session, source:Destination, endpoint_id:int, include_secret:bool=False):
    d=Destination(endpoint_id=endpoint_id,name=source.name,description=source.description,active=source.active,kind=source.kind,method=source.method,request_mode=getattr(source,'request_mode','custom'),url=source.url,query_params=dict(source.query_params or {}),headers=dict(source.headers or {}),auth_type=source.auth_type,auth_username=source.auth_username,auth_secret_encrypted=source.auth_secret_encrypted if include_secret else '',auth_header_name=source.auth_header_name,timeout_seconds=source.timeout_seconds,verify_tls=source.verify_tls,retry_attempts=source.retry_attempts,retry_delays=list(source.retry_delays or []),retry_exponential=source.retry_exponential,retry_statuses=list(source.retry_statuses or []),allow_private=source.allow_private,allow_localhost=source.allow_localhost)
    db.add(d);db.flush();return d

def clone_flow_to_endpoint(db:Session, source:Flow, endpoint_id:int, include_secrets:bool=False):
    nf=Flow(name=source.name+' Copy',endpoint_id=endpoint_id,active=False,mode=getattr(source,'mode','conditional') or 'conditional',condition_logic=source.condition_logic)
    db.add(nf);db.flush()
    for r in source.rules:
        db.add(FlowRule(flow_id=nf.id,position=r.position,field_path=r.field_path,operator=r.operator,value_json=r.value_json))
    for m in source.mappings:
        db.add(Mapping(flow_id=nf.id,position=m.position,target_path=m.target_path,source_type=m.source_type,source_value=m.source_value,static_type=m.static_type,fallback_json=m.fallback_json,transforms=list(m.transforms or [])))
    dest_cache={}
    for route in source.routes:
        if not route.destination: continue
        key=route.destination.id
        if key not in dest_cache: dest_cache[key]=clone_destination(db,route.destination,endpoint_id,include_secrets)
        nr=FlowDestination(flow_id=nf.id,destination_id=dest_cache[key].id,branch=route.branch);db.add(nr);db.flush()
        for m in getattr(route,'mappings',[]) or []:
            db.add(RouteMapping(route_id=nr.id,position=m.position,target_path=m.target_path,source_type=m.source_type,source_value=m.source_value,static_type=m.static_type,fallback_json=m.fallback_json,transforms=list(m.transforms or [])))
    return nf

@router.get('/')
def root(request:Request,db:Session=Depends(get_db)):
    if db.scalar(select(func.count(User.id)))==0:return RedirectResponse('/setup',303)
    try: require_user(request,db);return RedirectResponse('/dashboard',303)
    except: return RedirectResponse('/login',303)

@router.get('/dashboard')
def dashboard(request:Request,db:Session=Depends(get_db)):
    require_user(request,db)
    from datetime import datetime,timezone
    today=datetime.now(timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0)
    stats={
      'requests':db.scalar(select(func.count(Event.id)).where(Event.received_at>=today)) or 0,
      'success':db.scalar(select(func.count(Delivery.id)).where(Delivery.status=='success',Delivery.created_at>=today)) or 0,
      'failed':db.scalar(select(func.count(Delivery.id)).where(Delivery.status=='failed',Delivery.created_at>=today)) or 0,
      'retrying':db.scalar(select(func.count(Delivery.id)).where(Delivery.status=='retrying')) or 0,
      'endpoints':db.scalar(select(func.count(IncomingEndpoint.id)).where(IncomingEndpoint.active==True)) or 0,
      'destinations':db.scalar(select(func.count(Destination.id)).where(Destination.active==True)) or 0,
    }
    events=db.scalars(select(Event).order_by(Event.received_at.desc()).limit(12)).all();rows=[]
    for e in events:
        d=db.scalar(select(Delivery).where(Delivery.event_id==e.id).order_by(Delivery.created_at.desc()).limit(1));flow=db.get(Flow,d.flow_id) if d and d.flow_id else None;rows.append({'event':e,'delivery':d,'flow':flow})
    return render(request,db,'dashboard.html',stats=stats,event_rows=rows)

@router.get('/endpoints')
def endpoints(request:Request,db:Session=Depends(get_db)):
    return render(request,db,'endpoints.html',items=db.scalars(select(IncomingEndpoint).order_by(IncomingEndpoint.name)).all())

@router.get('/endpoints/new')
def endpoint_new(request:Request,db:Session=Depends(get_db)):
    return render(request,db,'endpoint_form.html',item=None)

@router.get('/endpoints/{eid}')
def endpoint_detail(eid:int,request:Request,db:Session=Depends(get_db)):
    ep=db.get(IncomingEndpoint,eid)
    if not ep:raise HTTPException(404)
    event_count=db.scalar(select(func.count(Event.id)).where(Event.endpoint_id==eid)) or 0
    events=db.scalars(select(Event).where(Event.endpoint_id==eid).order_by(Event.received_at.desc()).limit(6)).all()
    has_more=len(events)>5;events=events[:5]
    flows=db.scalars(select(Flow).where(Flow.endpoint_id==eid).order_by(Flow.name)).all()
    more_url=f'/endpoints/{eid}/events-more?offset=5' if has_more else ''
    return render(request,db,'endpoint_detail.html',item=ep,events=events,event_count=event_count,events_more_url=more_url,flows=flows,base_url=settings.app_base_url.rstrip('/'))

@router.get('/endpoints/{eid}/events-more')
def endpoint_events_more(eid:int,request:Request,offset:int=5,db:Session=Depends(get_db)):
    ep=db.get(IncomingEndpoint,eid)
    if not ep:raise HTTPException(404)
    offset=max(0,offset);rows=db.scalars(select(Event).where(Event.endpoint_id==eid).order_by(Event.received_at.desc()).offset(offset).limit(6)).all()
    has_more=len(rows)>5;items=rows[:5]
    response=render_fragment(request,db,'endpoint_event_rows.html',items=items,item=ep)
    response.headers['X-Next-URL']=f'/endpoints/{eid}/events-more?offset={offset+5}' if has_more else ''
    return response

@router.get('/endpoints/{eid}/edit')
def endpoint_edit(eid:int,request:Request,db:Session=Depends(get_db)):
    ep=db.get(IncomingEndpoint,eid)
    if not ep:raise HTTPException(404)
    return render(request,db,'endpoint_form.html',item=ep)

@router.post('/endpoints/save')
async def endpoint_save(request:Request,db:Session=Depends(get_db)):
    f=await form_with_csrf(request); eid=int(f.get('id') or 0);ep=db.get(IncomingEndpoint,eid) if eid else IncomingEndpoint()
    slug=safe_slug(f.get('slug') or secrets.token_hex(4))
    existing=db.scalar(select(IncomingEndpoint).where(IncomingEndpoint.slug==slug, IncomingEndpoint.id!=(eid or -1)))
    if existing:return render(request,db,'endpoint_form.html',item=ep,error='Endpoint-Bezeichnung bereits vergeben.')
    ep.name=(f.get('name') or '').strip();ep.description=(f.get('description') or '').strip();ep.slug=slug;ep.active=f.get('active')=='on';ep.methods=validate_methods([x.upper() for x in f.getlist('methods')] or ['POST']);ep.content_types=validate_content_types(parse_lines(f.get('content_types')) or ['*/*']);ep.max_payload_bytes=form_int(f,'max_payload_bytes',1048576,1024,100*1024*1024);ep.rate_limit_per_minute=form_int(f,'rate_limit_per_minute',120,1,100000);ep.request_timeout_seconds=form_int(f,'request_timeout_seconds',15,1,300);ep.ip_allowlist=parse_lines(f.get('ip_allowlist'));ep.ip_denylist=parse_lines(f.get('ip_denylist'));ep.synchronous=f.get('synchronous')=='on';ep.retention_success_days=form_int(f,'retention_success_days',0,1,36500) if f.get('retention_success_days') else None;ep.retention_failed_days=form_int(f,'retention_failed_days',0,1,36500) if f.get('retention_failed_days') else None
    if not ep.name:raise HTTPException(400,'Name erforderlich')
    try:validate_cidrs(ep.ip_allowlist);validate_cidrs(ep.ip_denylist);validate_header_name((f.get('auth_header_name') or '').strip())
    except ValueError as e:return render(request,db,'endpoint_form.html',item=ep,error=str(e))
    if not eid: db.add(ep);db.flush(); ep.auth=EndpointAuth()
    a=ep.auth or EndpointAuth(endpoint_id=ep.id);a.auth_type=f.get('auth_type') or 'none';a.username=(f.get('auth_username') or '').strip();a.header_name=(f.get('auth_header_name') or '').strip();a.hmac_algorithm=f.get('hmac_algorithm') or 'sha256';a.hmac_payload_basis=f.get('hmac_payload_basis') or 'raw_body';a.hmac_payload_template=(f.get('hmac_payload_template') or '{{raw_body}}').strip();a.hmac_signature_prefix=f.get('hmac_signature_prefix') or '';a.hmac_verify_timestamp=f.get('hmac_verify_timestamp')=='on';a.hmac_timestamp_header=(f.get('hmac_timestamp_header') or '').strip();a.hmac_timestamp_tolerance_seconds=form_int(f,'hmac_timestamp_tolerance_seconds',300,1,86400);new_secret=f.get('auth_secret') or ''
    if a.auth_type!='none' and not new_secret and not a.secret_encrypted:return render(request,db,'endpoint_form.html',item=ep,error='Secret ist für diese Authentifizierung erforderlich.')
    if a.auth_type=='basic' and not a.username:return render(request,db,'endpoint_form.html',item=ep,error='Benutzername ist für Basic Auth erforderlich.')
    try:
        validate_header_name(a.header_name)
        if a.auth_type=='hmac':
            if a.hmac_payload_basis=='custom':validate_hmac_template(a.hmac_payload_template)
            if a.hmac_verify_timestamp:
                validate_header_name(a.hmac_timestamp_header)
                if not a.hmac_timestamp_header:return render(request,db,'endpoint_form.html',item=ep,error='Timestamp-Header ist für die HMAC Timestamp-Prüfung erforderlich.')
            if '\r' in a.hmac_signature_prefix or '\n' in a.hmac_signature_prefix:return render(request,db,'endpoint_form.html',item=ep,error='Ungültiges HMAC Signatur-Präfix.')
    except ValueError as exc:return render(request,db,'endpoint_form.html',item=ep,error=str(exc))
    if new_secret:a.secret_encrypted=encrypt(new_secret)
    if not ep.auth:db.add(a)
    db.commit();return RedirectResponse(f'/endpoints/{ep.id}',303)

@router.post('/endpoints/{eid}/delete')
async def endpoint_delete(eid:int,request:Request,db:Session=Depends(get_db)):
    await form_with_csrf(request);ep=db.get(IncomingEndpoint,eid)
    if ep:db.delete(ep);db.commit()
    return RedirectResponse('/endpoints',303)


@router.post('/endpoints/{eid}/duplicate')
async def endpoint_duplicate(eid:int,request:Request,db:Session=Depends(get_db)):
    f=await form_with_csrf(request);src=db.get(IncomingEndpoint,eid)
    if not src: raise HTTPException(404)
    slug=safe_slug(src.slug+'-copy');base=slug;n=1
    while db.scalar(select(IncomingEndpoint).where(IncomingEndpoint.slug==slug)):
        n+=1;slug=f'{base}-{n}'
    ep=IncomingEndpoint(name=src.name+' Copy',description=src.description,slug=slug,active=False,methods=list(src.methods or []),content_types=list(src.content_types or []),max_payload_bytes=src.max_payload_bytes,rate_limit_per_minute=src.rate_limit_per_minute,request_timeout_seconds=src.request_timeout_seconds,ip_allowlist=list(src.ip_allowlist or []),ip_denylist=list(src.ip_denylist or []),synchronous=src.synchronous,retention_success_days=src.retention_success_days,retention_failed_days=src.retention_failed_days)
    db.add(ep);db.flush();sa=src.auth
    ep.auth=EndpointAuth(auth_type=sa.auth_type if sa else 'none',username=sa.username if sa else '',secret_encrypted=sa.secret_encrypted if sa and f.get('include_secrets')=='on' else '',header_name=sa.header_name if sa else '',hmac_algorithm=sa.hmac_algorithm if sa else 'sha256',hmac_payload_basis=sa.hmac_payload_basis if sa else 'raw_body',hmac_payload_template=sa.hmac_payload_template if sa else '{{raw_body}}',hmac_signature_prefix=sa.hmac_signature_prefix if sa else '',hmac_verify_timestamp=sa.hmac_verify_timestamp if sa else False,hmac_timestamp_header=sa.hmac_timestamp_header if sa else '',hmac_timestamp_tolerance_seconds=sa.hmac_timestamp_tolerance_seconds if sa else 300)
    for flow in db.scalars(select(Flow).where(Flow.endpoint_id==src.id).order_by(Flow.id)).all(): clone_flow_to_endpoint(db,flow,ep.id,f.get('include_secrets')=='on')
    db.commit();return RedirectResponse(f'/endpoints/{ep.id}',303)

@router.get('/endpoints/{eid}/flows/new')
def endpoint_flow_wizard(eid:int,request:Request,db:Session=Depends(get_db)):
    ep=db.get(IncomingEndpoint,eid)
    if not ep: raise HTTPException(404)
    existing=db.scalars(select(Flow).order_by(Flow.created_at.desc())).all()
    return render(request,db,'flow_wizard.html',item=ep,existing_flows=existing)

@router.post('/endpoints/{eid}/flows/new')
async def endpoint_flow_create(eid:int,request:Request,db:Session=Depends(get_db)):
    f=await form_with_csrf(request);ep=db.get(IncomingEndpoint,eid)
    if not ep: raise HTTPException(404)
    mode=f.get('mode') or 'direct'
    if mode=='copy':
        src=db.get(Flow,form_int(f,'copy_flow_id',0,1))
        if not src: raise HTTPException(404)
        flow=clone_flow_to_endpoint(db,src,eid,False)
        flow.name=src.name+' Copy';db.commit()
    else:
        if mode not in ('direct','conditional'): raise HTTPException(400,'Ungültiger Flow-Typ')
        flow=Flow(name='Direkt' if mode=='direct' else 'Entweder / Oder',endpoint_id=eid,active=(mode=='direct'),mode=mode,condition_logic='AND');db.add(flow);db.commit();db.refresh(flow)
    suffix='?new_target=1' if mode=='direct' else ''
    return RedirectResponse(f'/endpoints/{eid}/flows/{flow.id}/edit{suffix}',303)

@router.get('/endpoints/{eid}/flows/{fid}/edit')
def endpoint_flow_edit(eid:int,fid:int,request:Request,sample_event:int|None=None,new_target:int=0,db:Session=Depends(get_db)):
    ep=db.get(IncomingEndpoint,eid);flow=db.get(Flow,fid)
    if not ep or not flow or flow.endpoint_id!=eid: raise HTTPException(404)
    if flow.mode=='direct':
        sample,paths,events=None,[],[]
    else:
        sample,paths,events=sample_data_for_endpoint(db,eid,sample_event)
    return render(request,db,'flow_editor.html',endpoint=ep,item=flow,sample_event=sample,sample_paths=paths,sample_events=events,sample_context=(event_context(sample) if sample else {}),auto_target=bool(new_target and flow.mode=='direct' and not flow.routes))

@router.post('/endpoints/{eid}/flows/{fid}/save')
async def endpoint_flow_save(eid:int,fid:int,request:Request,db:Session=Depends(get_db)):
    f=await form_with_csrf(request);flow=db.get(Flow,fid)
    if not flow or flow.endpoint_id!=eid: raise HTTPException(404)
    flow.name=(f.get('name') or '').strip() or ('Direkt' if flow.mode=='direct' else 'Entweder / Oder')
    flow.active=f.get('active')=='on';flow.condition_logic=f.get('condition_logic') if f.get('condition_logic') in ('AND','OR') else 'AND'
    if flow.mode=='direct':
        for x in list(flow.rules): db.delete(x)
    else:
        for x in list(flow.rules): db.delete(x)
        db.flush()
        for i in range(50):
            field=(f.get(f'rule_field_{i}') or '').strip()
            if not field: continue
            db.add(FlowRule(flow_id=flow.id,position=i,field_path=field,operator=validate_rule_operator(f.get(f'rule_operator_{i}') or 'equals'),value_json=jsonish(f.get(f'rule_value_{i}'))))
    db.commit()
    if request.headers.get('X-Requested-With')=='fetch':return JSONResponse({'ok':True})
    return RedirectResponse(f'/endpoints/{eid}/flows/{fid}/edit',303)

@router.post('/endpoints/{eid}/flows/{fid}/delete')
async def endpoint_flow_delete(eid:int,fid:int,request:Request,db:Session=Depends(get_db)):
    await form_with_csrf(request);flow=db.get(Flow,fid)
    if flow and flow.endpoint_id==eid: db.delete(flow);db.commit()
    return RedirectResponse(f'/endpoints/{eid}',303)

@router.get('/endpoints/{eid}/flows/{fid}/targets/new')
def endpoint_target_new(eid:int,fid:int,request:Request,sample_event:int|None=None,branch:str='always',modal:bool=False,db:Session=Depends(get_db)):
    ep=db.get(IncomingEndpoint,eid);flow=db.get(Flow,fid)
    if not ep or not flow or flow.endpoint_id!=eid: raise HTTPException(404)
    sample,paths,events=sample_data_for_endpoint(db,eid,sample_event)
    sample_context=event_context(sample) if sample else {}
    sample_body=event_payload(sample) if sample else {}
    body_paths=flatten_paths(sample_body) if sample else []
    aux_paths=[x for x in paths if x[0].startswith(('headers.','query.','meta.'))]
    template='target_editor_fragment.html' if modal else 'target_editor.html'
    return render(request,db,template,endpoint=ep,flow=flow,item=None,route=None,branch=branch,sample_event=sample,sample_paths=body_paths,sample_aux_paths=aux_paths,sample_events=events,sample_context=sample_context,sample_body=sample_body,error=None,modal=modal)

@router.get('/endpoints/{eid}/flows/{fid}/targets/{rid}/edit')
def endpoint_target_edit(eid:int,fid:int,rid:int,request:Request,sample_event:int|None=None,modal:bool=False,db:Session=Depends(get_db)):
    flow=db.get(Flow,fid);route=db.get(FlowDestination,rid)
    if not flow or flow.endpoint_id!=eid or not route or route.flow_id!=fid: raise HTTPException(404)
    sample,paths,events=sample_data_for_endpoint(db,eid,sample_event)
    sample_context=event_context(sample) if sample else {}
    sample_body=event_payload(sample) if sample else {}
    body_paths=flatten_paths(sample_body) if sample else []
    aux_paths=[x for x in paths if x[0].startswith(('headers.','query.','meta.'))]
    template='target_editor_fragment.html' if modal else 'target_editor.html'
    return render(request,db,template,endpoint=flow.endpoint,flow=flow,item=route.destination,route=route,branch=route.branch,sample_event=sample,sample_paths=body_paths,sample_aux_paths=aux_paths,sample_events=events,sample_context=sample_context,sample_body=sample_body,error=None,modal=modal)

@router.post('/endpoints/{eid}/flows/{fid}/targets/save')
async def endpoint_target_save(eid:int,fid:int,request:Request,db:Session=Depends(get_db)):
    f=await form_with_csrf(request);flow=db.get(Flow,fid)
    if not flow or flow.endpoint_id!=eid: raise HTTPException(404)
    rid=int(f.get('route_id') or 0);route=db.get(FlowDestination,rid) if rid else None
    if route and route.flow_id!=fid: raise HTTPException(404)
    d=route.destination if route else Destination(endpoint_id=eid)
    url=(f.get('url') or '').strip()
    try: validate_destination_url(url,allow_private=True,allow_localhost=True,resolve=False)
    except SSRFError as e:
        sample,paths,events=sample_data_for_endpoint(db,eid,int(f.get('sample_event_id') or 0) or None)
        is_modal=f.get('modal')=='1';template='target_editor_fragment.html' if is_modal else 'target_editor.html'
        return render(request,db,template,endpoint=flow.endpoint,flow=flow,item=d,route=route,branch=f.get('branch') or 'always',sample_event=sample,sample_paths=(flatten_paths(event_payload(sample)) if sample else []),sample_aux_paths=([x for x in paths if x[0].startswith(('headers.','query.','meta.'))] if sample else []),sample_events=events,sample_context=(event_context(sample) if sample else {}),sample_body=(event_payload(sample) if sample else {}),error=str(e),modal=is_modal)
    d.endpoint_id=eid;d.name=(f.get('name') or '').strip() or destination_name_from_url(url)
    d.description=(f.get('description') or '').strip();d.active=f.get('active')=='on';d.kind='http';submitted_mode=f.get('request_mode');has_mapping=any((f.get(f'map_target_{i}') or '').strip() for i in range(100));d.request_mode=submitted_mode if submitted_mode in ('passthrough','custom') else ('custom' if has_mapping else 'passthrough');d.method=validate_methods([(f.get('method') or 'POST').upper()])[0];d.url=url;d.query_params=parse_kv(f.get('query_params'));d.headers=parse_kv(f.get('headers'));d.auth_type=f.get('auth_type') or 'none';d.auth_username=(f.get('auth_username') or '').strip();d.auth_header_name=(f.get('auth_header_name') or '').strip();new_secret=f.get('auth_secret') or ''
    validate_headers(d.headers);validate_header_name(d.auth_header_name)
    if d.auth_type!='none' and not new_secret and not d.auth_secret_encrypted: raise HTTPException(400,'Secret ist für diese Authentifizierung erforderlich')
    if new_secret:d.auth_secret_encrypted=encrypt(new_secret)
    d.timeout_seconds=form_int(f,'timeout_seconds',15,1,300);d.verify_tls=f.get('verify_tls')=='on';d.retry_attempts=form_int(f,'retry_attempts',5,1,20);d.retry_delays=[int(x) for x in parse_lines(f.get('retry_delays')) if x.isdigit()] or [30,120,600,1800];d.retry_exponential=f.get('retry_exponential')=='on';d.retry_statuses=[int(x) for x in parse_lines(f.get('retry_statuses')) if x.isdigit()] or [429,500,502,503,504];d.allow_private=f.get('allow_private')=='on';d.allow_localhost=f.get('allow_localhost')=='on'
    branch=f.get('branch') or ('always' if flow.mode=='direct' else 'matched')
    if branch not in ('matched','else','always'): raise HTTPException(400,'Ungültiger Branch')
    if not route:
        db.add(d);db.flush();route=FlowDestination(flow_id=fid,destination_id=d.id,branch=branch);db.add(route);db.flush()
    else: route.branch=branch
    if flow.mode=='direct': flow.active=True
    for m in list(route.mappings): db.delete(m)
    db.flush()
    for i in range(100 if d.request_mode=='custom' else 0):
        target=(f.get(f'map_target_{i}') or '').strip()
        if not target: continue
        validate_mapping_path(target);op=f.get(f'map_transform_{i}') or '';tr=[{'op':op,'arg':f.get(f'map_transform_arg_{i}') or ''}] if op else []
        db.add(RouteMapping(route_id=route.id,position=i,target_path=target,source_type=f.get(f'map_source_type_{i}') or 'field',source_value=f.get(f'map_source_{i}') or '',static_type=f.get(f'map_static_type_{i}') or 'string',fallback_json=jsonish(f.get(f'map_fallback_{i}')),transforms=tr))
    db.commit()
    if f.get('modal')=='1': return JSONResponse({'ok':True,'route_id':route.id,'destination_id':d.id})
    return RedirectResponse(f'/endpoints/{eid}/flows/{fid}/edit',303)

@router.post('/endpoints/{eid}/flows/{fid}/targets/{rid}/delete')
async def endpoint_target_delete(eid:int,fid:int,rid:int,request:Request,db:Session=Depends(get_db)):
    f=await form_with_csrf(request);route=db.get(FlowDestination,rid);flow=db.get(Flow,fid)
    if not route or not flow or flow.endpoint_id!=eid or route.flow_id!=fid: raise HTTPException(404)
    d=route.destination;db.delete(route);db.flush()
    if d and not db.scalar(select(func.count(FlowDestination.id)).where(FlowDestination.destination_id==d.id)): db.delete(d)
    db.commit()
    if f.get('modal')=='1': return JSONResponse({'ok':True})
    return RedirectResponse(f'/endpoints/{eid}/flows/{fid}/edit',303)


@router.get('/destinations')
def destinations(request:Request,db:Session=Depends(get_db)):
    require_user(request,db);return RedirectResponse('/endpoints',303)

@router.get('/destinations/new')
def destination_new(request:Request,db:Session=Depends(get_db)):
    require_user(request,db);return RedirectResponse('/endpoints',303)

@router.get('/destinations/{did}/edit')
def destination_edit(did:int,request:Request,db:Session=Depends(get_db)):
    item=db.get(Destination,did)
    if not item:raise HTTPException(404)
    route=db.scalar(select(FlowDestination).where(FlowDestination.destination_id==did).order_by(FlowDestination.id).limit(1))
    if route:
        flow=db.get(Flow,route.flow_id);return RedirectResponse(f'/endpoints/{flow.endpoint_id}/flows/{flow.id}/targets/{route.id}/edit',303)
    return RedirectResponse(f'/endpoints/{item.endpoint_id}' if item.endpoint_id else '/endpoints',303)

@router.post('/destinations/save')
async def destination_save(request:Request,db:Session=Depends(get_db)):
    require_user(request,db);raise HTTPException(410,'Ziele werden innerhalb eines Webhook-Flows konfiguriert.')

@router.post('/destinations/{did}/delete')
async def destination_delete(did:int,request:Request,db:Session=Depends(get_db)):
    await form_with_csrf(request);d=db.get(Destination,did)
    if d:db.delete(d);db.commit()
    return RedirectResponse('/destinations',303)

@router.get('/flows')
def flows(request:Request,db:Session=Depends(get_db)):
    require_user(request,db);return RedirectResponse('/endpoints',303)

@router.get('/flows/new')
def flow_new(request:Request,endpoint_id:int|None=None,db:Session=Depends(get_db)):
    require_user(request,db)
    return RedirectResponse(f'/endpoints/{endpoint_id}/flows/new' if endpoint_id else '/endpoints',303)

@router.get('/flows/{fid}/edit')
def flow_edit(fid:int,request:Request,db:Session=Depends(get_db)):
    item=db.get(Flow,fid)
    if not item:raise HTTPException(404)
    return RedirectResponse(f'/endpoints/{item.endpoint_id}/flows/{item.id}/edit',303)

@router.post('/flows/save')
async def flow_save(request:Request,db:Session=Depends(get_db)):
    require_user(request,db);raise HTTPException(410,'Flows werden innerhalb eines Webhooks konfiguriert.')

@router.post('/flows/{fid}/delete')
async def flow_delete(fid:int,request:Request,db:Session=Depends(get_db)):
    await form_with_csrf(request);o=db.get(Flow,fid)
    if o:db.delete(o);db.commit()
    return RedirectResponse('/flows',303)

def optional_filter_id(value:str|int|None):
    if value in (None,''): return None
    try:
        parsed=int(value)
    except (TypeError,ValueError):
        return None
    return parsed if parsed>0 else None

@router.get('/events')
def events(request:Request,q:str='',endpoint:str='',status:str='',destination:str='',source_ip:str='',date_from:str='',date_to:str='',offset:int=0,partial:bool=False,db:Session=Depends(get_db)):
    require_user(request,db);stmt=select(Event).order_by(Event.received_at.desc(),Event.id.desc())
    endpoint_id=optional_filter_id(endpoint);destination_id=optional_filter_id(destination)
    if q:stmt=stmt.where(or_(Event.request_id.ilike(f'%{q}%'),Event.search_blob.ilike(f'%{q}%')))
    if endpoint_id:stmt=stmt.where(Event.endpoint_id==endpoint_id)
    if status:stmt=stmt.where(Event.status==status)
    if source_ip:stmt=stmt.where(Event.source_ip==source_ip)
    from datetime import datetime, timezone
    if date_from:
        try: stmt=stmt.where(Event.received_at>=datetime.fromisoformat(date_from).replace(tzinfo=timezone.utc))
        except ValueError: pass
    if date_to:
        try: stmt=stmt.where(Event.received_at<=datetime.fromisoformat(date_to+'T23:59:59').replace(tzinfo=timezone.utc))
        except ValueError: pass
    if destination_id:stmt=stmt.join(Delivery,Delivery.event_id==Event.id).where(Delivery.destination_id==destination_id)
    offset=max(0,offset);rows=db.scalars(stmt.offset(offset).limit(16)).unique().all();has_more=len(rows)>15;items=rows[:15]
    base_params={'q':q,'endpoint':endpoint_id,'status':status,'destination':destination_id,'source_ip':source_ip,'date_from':date_from,'date_to':date_to}
    active_params={k:v for k,v in base_params.items() if v not in ('',None)}
    return_to='/events'+(('?'+urlencode(active_params)) if active_params else '')
    next_url='/events?'+urlencode({**active_params,'offset':offset+15,'partial':'true'}) if has_more else ''
    if partial:
        response=render_fragment(request,db,'event_rows.html',items=items,events_return_to=return_to)
        response.headers['X-Next-URL']=next_url
        return response
    eps=db.scalars(select(IncomingEndpoint).order_by(IncomingEndpoint.name)).all();dests=db.scalars(select(Destination).order_by(Destination.name)).all()
    return render(request,db,'events.html',items=items,endpoints=eps,destinations=dests,filters={**base_params},events_return_to=return_to,next_url=next_url)

@router.get('/events/compare')
def compare_query(first:int,second:int,request:Request,db:Session=Depends(get_db)):
    return compare(first,second,request,db)

@router.get('/events/{eid}')
def event_detail(eid:int,request:Request,return_to:str='',db:Session=Depends(get_db)):
    ev=db.get(Event,eid)
    if not ev:raise HTTPException(404)
    deliveries=db.scalars(select(Delivery).where(Delivery.event_id==eid).order_by(Delivery.created_at.desc(),Delivery.id.desc())).all();headers={h.name:h.masked_value for h in ev.headers};q=ev.query_masked;parsed=parse_json(ev.body_masked);paths=flatten_paths(parsed) if parsed is not None else []
    raw_lines=[f'{ev.method} /in/{ev.endpoint.slug}'+(('?'+ '&'.join(f'{k}={v}' for k,v in q.items())) if q else '')]+[f'{k}: {v}' for k,v in headers.items()]+['',ev.body_masked]
    back_url=safe_event_return_to(return_to,ev.endpoint_id)
    back_label='Events' if back_url.startswith('/events') else 'Dashboard' if back_url == '/dashboard' else ev.endpoint.name
    return render(request,db,'event_detail.html',item=ev,deliveries=deliveries,headers=headers,query=q,paths=paths,raw_preview='\n'.join(raw_lines),back_url=back_url,back_label=back_label)

@router.get('/events/{eid}/deliveries-fragment')
def event_deliveries_fragment(eid:int,request:Request,db:Session=Depends(get_db)):
    ev=db.get(Event,eid)
    if not ev:raise HTTPException(404)
    deliveries=db.scalars(select(Delivery).where(Delivery.event_id==eid).order_by(Delivery.created_at.desc(),Delivery.id.desc())).all()
    response=render_fragment(request,db,'delivery_rows.html',deliveries=deliveries,event=ev)
    response.headers['X-Event-Status']=ev.status or ''
    pending_event=(ev.status or '') not in ('processed','failed','rejected')
    pending_delivery=any((d.status or '') in ('queued','processing') for d in deliveries)
    response.headers['X-Deliveries-Pending']='1' if (pending_event or pending_delivery) else '0'
    response.headers['X-Delivery-Count']=str(len(deliveries))
    return response

@router.post('/events/{eid}/replay')
async def replay(eid:int,request:Request,db:Session=Depends(get_db)):
    await form_with_csrf(request);ev=db.get(Event,eid)
    if not ev:raise HTTPException(404)
    new=clone_event(db,ev);return RedirectResponse(f'/events/{new.id}',303)

@router.get('/events/{eid}/edit-replay')
def edit_replay_page(eid:int,request:Request,db:Session=Depends(get_db)):
    ev=db.get(Event,eid)
    if not ev:raise HTTPException(404)
    original=raw_headers(ev);display={k:('********' if k.lower() in ('authorization','proxy-authorization','cookie','set-cookie','x-api-key','x-auth-token') else v) for k,v in original.items()}
    return render(request,db,'edit_replay.html',item=ev,body=decrypt(ev.body_encrypted),headers=display,query=json.loads(decrypt(ev.query_encrypted) or '{}'))

@router.post('/events/{eid}/edit-replay')
async def edit_replay(eid:int,request:Request,db:Session=Depends(get_db)):
    f=await form_with_csrf(request);ev=db.get(Event,eid)
    if not ev:raise HTTPException(404)
    body=f.get('body') or '';headers=parse_kv(f.get('headers'));original=raw_headers(ev)
    for k,v in list(headers.items()):
        if v=='********':
            match=next((ov for ok,ov in original.items() if ok.lower()==k.lower()),None)
            if match is not None:headers[k]=match
    query=parse_kv(f.get('query'));method=f.get('method') or ev.method
    new=clone_event(db,ev,body_text=body,headers=headers,query=query,method=method);return RedirectResponse(f'/events/{new.id}',303)

@router.post('/events/{eid}/dry-run')
async def dry_run(eid:int,request:Request,db:Session=Depends(get_db)):
    await form_with_csrf(request);ev=db.get(Event,eid)
    if not ev:raise HTTPException(404)
    sims=simulate_event(db,ev);return render(request,db,'dry_run.html',item=ev,simulations=sims)

def _pretty_event_body(body:str):
    try:
        parsed=json.loads(body)
        return json.dumps(parsed,ensure_ascii=False,indent=2).splitlines()
    except Exception:
        return (body or '').splitlines() or ['']

def _side_by_side_diff(left:list[str],right:list[str]):
    import difflib
    rows=[]
    matcher=difflib.SequenceMatcher(a=left,b=right,autojunk=False)
    for tag,i1,i2,j1,j2 in matcher.get_opcodes():
        if tag=='equal':
            for offset in range(i2-i1):
                rows.append({'left_no':i1+offset+1,'left':left[i1+offset],'left_kind':'same','right_no':j1+offset+1,'right':right[j1+offset],'right_kind':'same'})
            continue
        if tag=='delete':
            for idx in range(i1,i2):
                rows.append({'left_no':idx+1,'left':left[idx],'left_kind':'removed','right_no':None,'right':'','right_kind':'empty'})
            continue
        if tag=='insert':
            for idx in range(j1,j2):
                rows.append({'left_no':None,'left':'','left_kind':'empty','right_no':idx+1,'right':right[idx],'right_kind':'added'})
            continue
        # replace: keep the two spans visually aligned; surplus lines remain one-sided.
        count=max(i2-i1,j2-j1)
        for offset in range(count):
            li=i1+offset;ri=j1+offset
            rows.append({
                'left_no':li+1 if li<i2 else None,'left':left[li] if li<i2 else '','left_kind':'removed' if li<i2 else 'empty',
                'right_no':ri+1 if ri<j2 else None,'right':right[ri] if ri<j2 else '','right_kind':'added' if ri<j2 else 'empty',
            })
    return rows

@router.get('/events/compare/{a}/{b}')
def compare(a:int,b:int,request:Request,db:Session=Depends(get_db)):
    first,second=db.get(Event,a),db.get(Event,b)
    if not first or not second:raise HTTPException(404)
    # Always compare chronologically: old -> current, independent of input order.
    old,current=sorted((first,second),key=lambda ev:(ev.received_at,ev.id))
    left=_pretty_event_body(old.body_masked);right=_pretty_event_body(current.body_masked)
    rows=_side_by_side_diff(left,right)
    changed=sum(1 for row in rows if row['left_kind']!='same' or row['right_kind']!='same')
    return render(request,db,'compare.html',old=old,current=current,rows=rows,changed=changed)

@router.post('/deliveries/{did}/retry')
async def retry(did:int,request:Request,db:Session=Depends(get_db)):
    await form_with_csrf(request);d=manual_retry(db,did)
    if not d:raise HTTPException(404)
    return RedirectResponse(f'/events/{d.event_id}',303)

@router.get('/deliveries/{did}')
def delivery_detail(did:int,request:Request,db:Session=Depends(get_db)):
    d=db.get(Delivery,did)
    if not d:raise HTTPException(404)
    ev=db.get(Event,d.event_id)
    if not ev:raise HTTPException(404)
    attempts=db.scalars(select(DeliveryAttempt).where(DeliveryAttempt.delivery_id==did).order_by(DeliveryAttempt.attempt_no.desc())).all()
    return render(request,db,'delivery_detail.html',item=d,event=ev,endpoint=ev.endpoint,attempts=attempts)

@router.get('/deliveries/{did}/live-fragment')
def delivery_live_fragment(did:int,request:Request,db:Session=Depends(get_db)):
    d=db.get(Delivery,did)
    if not d:raise HTTPException(404)
    ev=db.get(Event,d.event_id)
    if not ev:raise HTTPException(404)
    attempts=db.scalars(select(DeliveryAttempt).where(DeliveryAttempt.delivery_id==did).order_by(DeliveryAttempt.attempt_no.desc())).all()
    summary=render_fragment(request,db,'delivery_live_fragment.html',item=d,event=ev,endpoint=ev.endpoint).body.decode()
    attempt_rows=render_fragment(request,db,'delivery_attempt_rows.html',attempts=attempts).body.decode()
    return JSONResponse({'status':d.status or '','response':d.response_masked or '', 'summary_html':summary,'attempts_html':attempt_rows})

@router.get('/deliveries/{did}/edit-retry')
def delivery_edit_retry_page(did:int,request:Request,db:Session=Depends(get_db)):
    d=db.get(Delivery,did)
    if not d:raise HTTPException(404)
    req=json.loads(decrypt(d.final_request_encrypted) or '{}')
    body_mode=req.get('body_mode') or 'json'
    body=req.get('body')
    body_text=(body if isinstance(body,str) else '' if body is None else str(body)) if body_mode=='raw' else json.dumps(body,ensure_ascii=False,indent=2)
    return render(request,db,'delivery_edit_retry.html',item=d,req=req,body_mode=body_mode,body_text=body_text)

@router.post('/deliveries/{did}/edit-retry')
async def delivery_edit_retry(did:int,request:Request,db:Session=Depends(get_db)):
    f=await form_with_csrf(request);d=db.get(Delivery,did)
    if not d:raise HTTPException(404)
    current=json.loads(decrypt(d.final_request_encrypted) or '{}')
    body_mode=(f.get('body_mode') or current.get('body_mode') or 'json').strip().lower()
    if body_mode not in ('json','raw'):body_mode='json'
    raw_body=f.get('body') or ''
    body_encoding=(f.get('body_encoding') or current.get('body_encoding') or '').strip().lower()
    if body_mode=='raw':
        body=raw_body
        if body_encoding=='base64':
            import base64
            try:base64.b64decode(body,validate=True)
            except Exception:
                req={'method':f.get('method') or current.get('method') or 'POST','url':f.get('url') or current.get('url') or '','headers':parse_kv(f.get('headers')),'query':parse_kv(f.get('query')),'body_mode':'raw','body':raw_body,'body_encoding':'base64'}
                return render(request,db,'delivery_edit_retry.html',item=d,req=req,body_mode='raw',body_text=raw_body,error='Body ist kein gültiges Base64.')
    else:
        body_encoding=''
        try: body=json.loads(raw_body) if raw_body.strip() else None
        except Exception:
            req={'method':f.get('method') or current.get('method') or 'POST','url':f.get('url') or current.get('url') or '','headers':parse_kv(f.get('headers')),'query':parse_kv(f.get('query')),'body_mode':'json','body':raw_body}
            return render(request,db,'delivery_edit_retry.html',item=d,req=req,body_mode='json',body_text=raw_body,error='Body ist kein gültiges JSON.')
    req={'method':(f.get('method') or current.get('method') or 'POST').upper(),'url':(f.get('url') or current.get('url') or '').strip(),'headers':parse_kv(f.get('headers')),'query':parse_kv(f.get('query')),'body_mode':body_mode,'body':body}
    if body_mode=='raw' and body_encoding=='base64':req['body_encoding']='base64'
    dest=d.destination
    allow_private=settings.allow_private_destinations or bool(dest and dest.allow_private)
    allow_localhost=settings.allow_localhost_destinations or bool(dest and dest.allow_localhost)
    try:validate_destination_url(req['url'],allow_private=allow_private,allow_localhost=allow_localhost)
    except SSRFError as e:return render(request,db,'delivery_edit_retry.html',item=d,req=req,body_mode=body_mode,body_text=raw_body,error=str(e))
    d.final_request_encrypted=encrypt(json.dumps(req,ensure_ascii=False))
    d.final_request_masked=json.dumps(mask_json(req,get_setting(db,'mask_fields',[]) or []),ensure_ascii=False,indent=2)
    db.commit();manual_retry(db,d.id)
    return RedirectResponse(f'/deliveries/{d.id}',303)

@router.get('/api/docs')
def api_docs(request:Request,db:Session=Depends(get_db)):
    require_user(request,db);spec=request.app.openapi();paths=[]
    for path,methods in spec.get('paths',{}).items():
        if not path.startswith('/api/v1/'):continue
        for method,meta in methods.items():
            if method.lower() not in ('get','post','put','patch','delete'):continue
            paths.append({'method':method.upper(),'path':path,'summary':meta.get('summary') or meta.get('operationId','')})
    return render(request,db,'api_docs.html',paths=paths)

def settings_view_context(db:Session, **extra):
    return {'trusted':'\n'.join(get_setting(db,'trusted_proxies',[]) or []),'mask_fields':'\n'.join(get_setting(db,'mask_fields',[]) or []),'error':None,'password_error':None,'password_notice':None,**extra}

@router.get('/settings')
def settings_page(request:Request,db:Session=Depends(get_db)):
    notice='Passwort wurde geändert. Alle anderen Sitzungen wurden beendet.' if request.query_params.get('password_changed')=='1' else None
    return render(request,db,'settings.html',**settings_view_context(db,password_notice=notice))

@router.post('/settings')
async def settings_save(request:Request,db:Session=Depends(get_db)):
    f=await form_with_csrf(request);trusted=parse_lines(f.get('trusted_proxies'))
    try:validate_cidrs(trusted)
    except ValueError as e:return render(request,db,'settings.html',**settings_view_context(db,trusted='\n'.join(trusted),mask_fields=f.get('mask_fields') or '',error=str(e)))
    set_setting(db,'trusted_proxies',trusted);set_setting(db,'mask_fields',parse_lines(f.get('mask_fields')));return RedirectResponse('/settings',303)

@router.post('/settings/password')
async def settings_password(request:Request,db:Session=Depends(get_db)):
    f=await form_with_csrf(request);user=require_user(request,db)
    current=str(f.get('current_password') or '');new=str(f.get('new_password') or '');confirm=str(f.get('confirm_password') or '')
    error=None
    if not verify_password(current,user.password_hash):error='Aktuelles Passwort ist nicht korrekt.'
    elif len(new)<10:error='Passwort muss mindestens 10 Zeichen haben.'
    elif new!=confirm:error='Die neuen Passwörter stimmen nicht überein.'
    elif verify_password(new,user.password_hash):error='Das neue Passwort muss sich vom aktuellen Passwort unterscheiden.'
    if error:
        response=render(request,db,'settings.html',**settings_view_context(db,password_error=error));response.status_code=400;return response
    user.password_hash=hash_password(new);user.session_version=int(getattr(user,'session_version',1) or 1)+1;db.commit();db.refresh(user)
    csrf=secrets.token_urlsafe(24);resp=RedirectResponse('/settings?password_changed=1',303)
    resp.set_cookie('zentwhook_session',sign_session(user.id,csrf,user.session_version),httponly=True,samesite='lax',secure=settings.cookie_secure,max_age=43200)
    return resp

@router.get('/settings/export')
def export_config(request:Request,db:Session=Depends(get_db)):
    require_user(request,db)
    eps=db.scalars(select(IncomingEndpoint)).all();dests=db.scalars(select(Destination)).all();flows=db.scalars(select(Flow)).all()
    data={'version':__version__,'endpoints':[],'destinations':[],'flows':[]}
    for e in eps:data['endpoints'].append({'name':e.name,'description':e.description,'slug':e.slug,'active':e.active,'methods':e.methods,'content_types':e.content_types,'max_payload_bytes':e.max_payload_bytes,'rate_limit_per_minute':e.rate_limit_per_minute,'ip_allowlist':e.ip_allowlist,'ip_denylist':e.ip_denylist,'auth_type':e.auth.auth_type if e.auth else 'none','auth_header_name':e.auth.header_name if e.auth else '','hmac_algorithm':e.auth.hmac_algorithm if e.auth else 'sha256','hmac_payload_basis':e.auth.hmac_payload_basis if e.auth else 'raw_body','hmac_payload_template':e.auth.hmac_payload_template if e.auth else '{{raw_body}}','hmac_signature_prefix':e.auth.hmac_signature_prefix if e.auth else '','hmac_verify_timestamp':e.auth.hmac_verify_timestamp if e.auth else False,'hmac_timestamp_header':e.auth.hmac_timestamp_header if e.auth else '','hmac_timestamp_tolerance_seconds':e.auth.hmac_timestamp_tolerance_seconds if e.auth else 300})
    for d in dests:data['destinations'].append({'endpoint':d.endpoint.name if d.endpoint else None,'name':d.name,'description':d.description,'active':d.active,'request_mode':getattr(d,'request_mode','custom'),'method':d.method,'url':d.url,'query_params':d.query_params,'headers':d.headers,'auth_type':d.auth_type,'auth_header_name':d.auth_header_name,'timeout_seconds':d.timeout_seconds,'verify_tls':d.verify_tls,'retry_attempts':d.retry_attempts,'retry_delays':d.retry_delays,'retry_statuses':d.retry_statuses})
    for f in flows:data['flows'].append({'name':f.name,'active':f.active,'mode':f.mode,'endpoint':f.endpoint.name,'condition_logic':f.condition_logic,'rules':[{'field':r.field_path,'operator':r.operator,'value':r.value_json} for r in f.rules],'mappings':[{'target':m.target_path,'source_type':m.source_type,'source':m.source_value,'static_type':m.static_type,'fallback':m.fallback_json,'transforms':m.transforms} for m in f.mappings],'routes':[{'destination':r.destination.name,'branch':r.branch,'mappings':[{'target':m.target_path,'source_type':m.source_type,'source':m.source_value,'static_type':m.static_type,'fallback':m.fallback_json,'transforms':m.transforms} for m in r.mappings]} for r in f.routes if r.destination]})
    body=json.dumps(data,ensure_ascii=False,indent=2);return Response(body,media_type='application/json',headers={'Content-Disposition':'attachment; filename="zentwhook-config.json"','Cache-Control':'no-store'})

@router.post('/settings/export-secrets')
async def export_config_secrets(request:Request,db:Session=Depends(get_db)):
    f=await form_with_csrf(request)
    if f.get('confirm')!='on':raise HTTPException(400,'Bestätigung erforderlich')
    eps=db.scalars(select(IncomingEndpoint)).all();dests=db.scalars(select(Destination)).all();flows=db.scalars(select(Flow)).all()
    data={'version':__version__,'contains_secrets':True,'endpoints':[],'destinations':[],'flows':[]}
    for e in eps:data['endpoints'].append({'name':e.name,'description':e.description,'slug':e.slug,'active':e.active,'methods':e.methods,'content_types':e.content_types,'max_payload_bytes':e.max_payload_bytes,'rate_limit_per_minute':e.rate_limit_per_minute,'ip_allowlist':e.ip_allowlist,'ip_denylist':e.ip_denylist,'auth_type':e.auth.auth_type if e.auth else 'none','auth_username':e.auth.username if e.auth else '','auth_header_name':e.auth.header_name if e.auth else '','auth_secret':decrypt(e.auth.secret_encrypted) if e.auth and e.auth.secret_encrypted else '','hmac_algorithm':e.auth.hmac_algorithm if e.auth else 'sha256','hmac_payload_basis':e.auth.hmac_payload_basis if e.auth else 'raw_body','hmac_payload_template':e.auth.hmac_payload_template if e.auth else '{{raw_body}}','hmac_signature_prefix':e.auth.hmac_signature_prefix if e.auth else '','hmac_verify_timestamp':e.auth.hmac_verify_timestamp if e.auth else False,'hmac_timestamp_header':e.auth.hmac_timestamp_header if e.auth else '','hmac_timestamp_tolerance_seconds':e.auth.hmac_timestamp_tolerance_seconds if e.auth else 300})
    for d in dests:data['destinations'].append({'endpoint':d.endpoint.name if d.endpoint else None,'name':d.name,'description':d.description,'active':d.active,'request_mode':getattr(d,'request_mode','custom'),'method':d.method,'url':d.url,'query_params':d.query_params,'headers':d.headers,'auth_type':d.auth_type,'auth_username':d.auth_username,'auth_header_name':d.auth_header_name,'auth_secret':decrypt(d.auth_secret_encrypted) if d.auth_secret_encrypted else '','timeout_seconds':d.timeout_seconds,'verify_tls':d.verify_tls,'retry_attempts':d.retry_attempts,'retry_delays':d.retry_delays,'retry_statuses':d.retry_statuses})
    for flow in flows:data['flows'].append({'name':flow.name,'active':flow.active,'mode':flow.mode,'endpoint':flow.endpoint.name,'condition_logic':flow.condition_logic,'rules':[{'field':r.field_path,'operator':r.operator,'value':r.value_json} for r in flow.rules],'mappings':[{'target':m.target_path,'source_type':m.source_type,'source':m.source_value,'static_type':m.static_type,'fallback':m.fallback_json,'transforms':m.transforms} for m in flow.mappings],'routes':[{'destination':r.destination.name,'branch':r.branch,'mappings':[{'target':m.target_path,'source_type':m.source_type,'source':m.source_value,'static_type':m.static_type,'fallback':m.fallback_json,'transforms':m.transforms} for m in r.mappings]} for r in flow.routes if r.destination]})
    body=json.dumps(data,ensure_ascii=False,indent=2);return Response(body,media_type='application/json',headers={'Content-Disposition':'attachment; filename="zentwhook-config-with-secrets.json"','Cache-Control':'no-store'})

@router.post('/settings/import')
async def import_config(request:Request,file:UploadFile=File(...),db:Session=Depends(get_db)):
    # Multipart CSRF is read here after FastAPI has parsed the upload.
    form=await request.form();request.state.form_csrf=form.get('_csrf');require_csrf(request)
    raw=await file.read(2*1024*1024+1)
    if len(raw)>2*1024*1024:raise HTTPException(413,'Import-Datei zu groß')
    try:data=json.loads(raw.decode())
    except Exception:raise HTTPException(400,'Ungültige JSON-Datei')
    ep_by_name={e.name:e for e in db.scalars(select(IncomingEndpoint)).all()};dest_by_key={(d.endpoint_id,d.name):d for d in db.scalars(select(Destination)).all()}
    for x in data.get('endpoints',[]):
        if x.get('name') in ep_by_name:continue
        slug=safe_slug(x.get('slug') or x.get('name','endpoint'));base=slug;n=1
        while db.scalar(select(IncomingEndpoint).where(IncomingEndpoint.slug==slug)):n+=1;slug=f'{base}-{n}'
        validate_cidrs(x.get('ip_allowlist',[]));validate_cidrs(x.get('ip_denylist',[]));validate_header_name(x.get('auth_header_name',''))
        e=IncomingEndpoint(name=x['name'],description=x.get('description',''),slug=slug,active=bool(x.get('active',True)),methods=x.get('methods',['POST']),content_types=x.get('content_types',['*/*']),max_payload_bytes=int(x.get('max_payload_bytes',1048576)),rate_limit_per_minute=int(x.get('rate_limit_per_minute',120)),ip_allowlist=x.get('ip_allowlist',[]),ip_denylist=x.get('ip_denylist',[]));db.add(e);db.flush();e.auth=EndpointAuth(auth_type=x.get('auth_type','none'),username=x.get('auth_username',''),header_name=x.get('auth_header_name',''),secret_encrypted=encrypt(x.get('auth_secret','')) if x.get('auth_secret') else '',hmac_algorithm=x.get('hmac_algorithm','sha256'),hmac_payload_basis=x.get('hmac_payload_basis','raw_body'),hmac_payload_template=x.get('hmac_payload_template','{{raw_body}}'),hmac_signature_prefix=x.get('hmac_signature_prefix',''),hmac_verify_timestamp=bool(x.get('hmac_verify_timestamp',False)),hmac_timestamp_header=x.get('hmac_timestamp_header',''),hmac_timestamp_tolerance_seconds=int(x.get('hmac_timestamp_tolerance_seconds',300)));ep_by_name[e.name]=e
    for x in data.get('destinations',[]):
        ep=ep_by_name.get(x.get('endpoint'))
        if not ep:
            continue
        if (ep.id,x.get('name')) in dest_by_key:continue
        validate_destination_url(x.get('url',''),allow_private=True,allow_localhost=True,resolve=False);validate_headers(x.get('headers',{}));validate_header_name(x.get('auth_header_name',''))
        d=Destination(endpoint_id=ep.id,name=x['name'],description=x.get('description',''),active=bool(x.get('active',True)),request_mode=x.get('request_mode','custom'),method=x.get('method','POST'),url=x['url'],query_params=x.get('query_params',{}),headers=x.get('headers',{}),auth_type=x.get('auth_type','none'),auth_username=x.get('auth_username',''),auth_header_name=x.get('auth_header_name',''),auth_secret_encrypted=encrypt(x.get('auth_secret','')) if x.get('auth_secret') else '',timeout_seconds=int(x.get('timeout_seconds',15)),verify_tls=bool(x.get('verify_tls',True)),retry_attempts=int(x.get('retry_attempts',5)),retry_delays=x.get('retry_delays',[30,120,600,1800]),retry_statuses=x.get('retry_statuses',[429,500,502,503,504]));db.add(d);db.flush();dest_by_key[(ep.id,d.name)]=d
    for x in data.get('flows',[]):
        if db.scalar(select(Flow).where(Flow.name==x.get('name'))):continue
        ep=ep_by_name.get(x.get('endpoint')); 
        if not ep:continue
        flow=Flow(name=x['name'],active=bool(x.get('active',True)),mode=x.get('mode','conditional'),endpoint_id=ep.id,condition_logic=x.get('condition_logic','AND'));db.add(flow);db.flush()
        for i,r in enumerate(x.get('rules',[])):db.add(FlowRule(flow_id=flow.id,position=i,field_path=r.get('field',''),operator=r.get('operator','equals'),value_json=r.get('value')))
        for i,m in enumerate(x.get('mappings',[])):db.add(Mapping(flow_id=flow.id,position=i,target_path=m.get('target',''),source_type=m.get('source_type','field'),source_value=m.get('source',''),static_type=m.get('static_type','string'),fallback_json=m.get('fallback'),transforms=m.get('transforms',[])))
        for r in x.get('routes',[]):
            d=dest_by_key.get((ep.id,r.get('destination')))
            if d:
                route=FlowDestination(flow_id=flow.id,destination_id=d.id,branch=r.get('branch','matched'));db.add(route);db.flush()
                for i,m in enumerate(r.get('mappings',[])): db.add(RouteMapping(route_id=route.id,position=i,target_path=m.get('target',''),source_type=m.get('source_type','field'),source_value=m.get('source',''),static_type=m.get('static_type','string'),fallback_json=m.get('fallback'),transforms=m.get('transforms',[])))
    db.commit();return RedirectResponse('/settings',303)
