from __future__ import annotations
from datetime import datetime, timezone, timedelta
import base64, json, logging, time, uuid
import httpx
from sqlalchemy import select, func, or_, delete
from sqlalchemy.orm import Session
from .models import Event, EventHeader, Job, Flow, Delivery, DeliveryAttempt, Setting, User, Destination
from .security import encrypt, decrypt, mask_json, mask_value
from .engine import parse_json, eval_flow, build_mapping
from .ssrf import validate_destination_url, SSRFError
from .config import settings
from .incoming_auth import check_endpoint_auth
log=logging.getLogger('zentwhook')

def utcnow(): return datetime.now(timezone.utc)

def get_setting(db,key,default=None):
    obj=db.get(Setting,key); return obj.value_json if obj else default

def set_setting(db,key,value):
    obj=db.get(Setting,key)
    if obj: obj.value_json=value
    else: db.add(Setting(key=key,value_json=value))
    db.commit()

def queue_job(db,kind,payload,run_at=None):
    j=Job(kind=kind,payload=payload,status='queued',run_at=run_at or utcnow());db.add(j);db.commit();return j

_BODY_B64_PREFIX='__zentwhook_b64__:'

def _encode_body_storage(body:bytes)->str:
    # Store exact request bytes in the existing encrypted Text column.  The
    # prefix keeps this backward compatible with events written before 0.3.12.
    return _BODY_B64_PREFIX+base64.b64encode(body).decode('ascii')

def event_body_bytes(event:Event)->bytes:
    raw=decrypt(event.body_encrypted)
    if raw.startswith(_BODY_B64_PREFIX):
        try:return base64.b64decode(raw[len(_BODY_B64_PREFIX):],validate=True)
        except Exception:return b''
    # Backward compatibility: older events stored decoded UTF-8 text.
    return raw.encode('utf-8')

def event_body_text(event:Event)->str:
    return event_body_bytes(event).decode('utf-8',errors='replace')

def event_payload(event:Event):
    raw=event_body_text(event)
    data=parse_json(raw)
    return data if data is not None else {'_raw':raw}

def create_event(db,endpoint,method,source_ip,content_type,body:bytes,headers:dict,query:dict,auth_ok=True,auth_message='OK',replay_of_id=None):
    start=time.perf_counter(); text=body.decode('utf-8',errors='replace'); parsed=parse_json(text)
    custom=get_setting(db,'mask_fields',[]) or []
    masked_obj=mask_json(parsed,custom) if parsed is not None else text
    masked_body=json.dumps(masked_obj,ensure_ascii=False,indent=2) if parsed is not None else text
    search_blob=' '.join([str(x) for x in [masked_body,source_ip,endpoint.name]])[:20000]
    ev=Event(processing_trace=[{'at':utcnow().isoformat(),'step':'received','status':'ok'},{'at':utcnow().isoformat(),'step':'authentication','status':'ok' if auth_ok else 'failed','message':auth_message}],request_id='req_'+uuid.uuid4().hex[:20],endpoint_id=endpoint.id,replay_of_id=replay_of_id,method=method,source_ip=source_ip,content_type=content_type,body_encrypted=encrypt(_encode_body_storage(body)),body_masked=masked_body,body_size=len(body),query_encrypted=encrypt(json.dumps(query,ensure_ascii=False)),query_masked=mask_json(query,custom),auth_ok=auth_ok,auth_message=auth_message,status='queued',search_blob=search_blob)
    db.add(ev);db.flush()
    for name,value in headers.items():
        db.add(EventHeader(event_id=ev.id,name=name,masked_value=str(mask_value(name,value)),encrypted_value=encrypt(str(value))))
    ev.processing_ms=(time.perf_counter()-start)*1000;db.commit();db.refresh(ev);return ev

def raw_headers(event): return {h.name:decrypt(h.encrypted_value) for h in event.headers}

def event_context(event:Event):
    raw=event_payload(event)
    data=dict(raw) if isinstance(raw,dict) else {'_raw':raw.get('_raw','') if isinstance(raw,dict) else raw}
    try:q=json.loads(decrypt(event.query_encrypted) or '{}')
    except Exception:q={}
    data.setdefault('headers',raw_headers(event))
    data.setdefault('query',q)
    data.setdefault('meta',{'request_id':event.request_id,'source_ip':event.source_ip,'method':event.method,'received_at':event.received_at.isoformat()})
    return data


PASSTHROUGH_DROP_HEADERS={
    'host','content-length','connection','keep-alive','proxy-authenticate',
    'proxy-authorization','te','trailer','transfer-encoding','upgrade',
    # Incoming authentication/session credentials must never leak to a target
    # just because passthrough mode is enabled. They can be configured on the
    # destination explicitly when required.
    'authorization','cookie','set-cookie','x-api-key','x-auth-token'
}

def event_query(event:Event):
    try:return json.loads(decrypt(event.query_encrypted) or '{}')
    except Exception:return {}

def passthrough_headers(event:Event):
    out={}
    for name,value in raw_headers(event).items():
        if name.lower() in PASSTHROUGH_DROP_HEADERS:continue
        out[name]=value
    if event.content_type and not any(k.lower()=='content-type' for k in out):
        out['Content-Type']=event.content_type
    return out

def _raw_request_body(event:Event):
    body=event_body_bytes(event)
    try:
        return {'body':body.decode('utf-8')}
    except UnicodeDecodeError:
        return {'body':base64.b64encode(body).decode('ascii'),'body_encoding':'base64'}

def destination_request(event:Event,dest:Destination,body):
    if getattr(dest,'request_mode','custom')=='passthrough':
        headers=passthrough_headers(event);headers.update(dest.headers or {})
        query=event_query(event);query.update(dest.query_params or {})
        return {
            'method':event.method,
            'url':dest.url,
            'headers':headers,
            'query':query,
            'body_mode':'raw',
            **(_raw_request_body(event)),
        }
    return {
        'method':dest.method,
        'url':dest.url,
        'headers':dest.headers or {},
        'query':dest.query_params or {},
        'body_mode':'json',
        'body':body,
    }

def simulate_event(db,event):
    payload=event_payload(event);data=event_context(event); flows=db.scalars(select(Flow).where(Flow.endpoint_id==event.endpoint_id,Flow.active==True).order_by(Flow.id)).all()
    results=[]
    for flow in flows:
        matched=eval_flow(data,flow)
        try: outgoing=build_mapping(data,flow.mappings) if flow.mappings else payload; map_ok=True; map_err=''
        except Exception as e: outgoing={};map_ok=False;map_err=str(e)
        routes=[]
        for r in flow.routes:
            eligible=r.branch=='always' or (r.branch=='matched' and matched) or (r.branch=='else' and not matched)
            if eligible and r.destination and r.destination.active:
                try:
                    if r.mappings:
                        route_body=build_mapping(data,r.mappings)
                    elif map_ok:
                        route_body=outgoing
                    else:
                        raise ValueError(map_err or 'Flow-Mapping fehlgeschlagen')
                    request_spec=destination_request(event,r.destination,route_body)
                    preview_body=parse_json(request_spec['body']) if request_spec.get('body_mode')=='raw' and request_spec.get('body_encoding')!='base64' else request_spec.get('body')
                    if request_spec.get('body_mode')=='raw' and preview_body is None: preview_body=request_spec.get('body','')
                    routes.append({'destination_id':r.destination.id,'destination':r.destination.name,'method':request_spec['method'],'url':r.destination.url,'body':preview_body,'request':request_spec,'request_mode':getattr(r.destination,'request_mode','custom'),'mapping_ok':True,'mapping_error':''})
                except Exception as exc:
                    routes.append({'destination_id':r.destination.id,'destination':r.destination.name,'method':r.destination.method,'url':r.destination.url,'body':{},'mapping_ok':False,'mapping_error':str(exc)})
        results.append({'flow_id':flow.id,'flow':flow.name,'matched':matched,'mapping_ok':map_ok,'mapping_error':map_err,'outgoing':outgoing,'routes':routes})
    return results

def process_event(db,event_id:int,dry_run=False):
    ev=db.get(Event,event_id)
    if not ev:return []
    ev.status='processing';trace=list(ev.processing_trace or []);trace.append({'at':utcnow().isoformat(),'step':'processing','status':'started'});ev.processing_trace=trace;db.commit()
    simulations=simulate_event(db,ev)
    if dry_run:
        ev.status='queued';db.commit();return simulations
    any_failure=False;created=0
    for sim in simulations:
        trace=list(ev.processing_trace or []);trace.append({'at':utcnow().isoformat(),'step':'rule','flow':sim['flow'],'status':'matched' if sim['matched'] else 'not_matched'});trace.append({'at':utcnow().isoformat(),'step':'transformation','flow':sim['flow'],'status':'ok' if sim['mapping_ok'] else 'failed','message':sim['mapping_error']});ev.processing_trace=trace;db.commit()
        for route in sim['routes']:
            if not route.get('mapping_ok', True):
                any_failure=True
                trace=list(ev.processing_trace or []);trace.append({'at':utcnow().isoformat(),'step':'transformation','flow':sim['flow'],'destination':route.get('destination'),'status':'failed','message':route.get('mapping_error','')});ev.processing_trace=trace;db.commit()
                continue
            dest=db.get(Destination,route['destination_id'])
            existing=db.scalar(select(Delivery).where(Delivery.event_id==ev.id,Delivery.flow_id==sim['flow_id'],Delivery.destination_id==dest.id))
            if existing:continue
            req=route.get('request') or destination_request(ev,dest,route['body'])
            d=Delivery(event_id=ev.id,flow_id=sim['flow_id'],destination_id=dest.id,status='queued',final_request_encrypted=encrypt(json.dumps(req,ensure_ascii=False)),final_request_masked=json.dumps(mask_json(req,get_setting(db,'mask_fields',[]) or []),ensure_ascii=False,indent=2))
            db.add(d);db.flush();created+=1
            trace=list(ev.processing_trace or []);trace.append({'at':utcnow().isoformat(),'step':'delivery_queued','destination':dest.name,'delivery_id':d.id});ev.processing_trace=trace;db.commit()
            try:
                perform_delivery(db,d,dest);trace=list(ev.processing_trace or []);trace.append({'at':utcnow().isoformat(),'step':'delivery','destination':dest.name,'delivery_id':d.id,'status':d.status,'http_status':d.http_status});ev.processing_trace=trace;db.commit()
            except Exception:
                log.exception('delivery processing failed request_id=%s delivery_id=%s',ev.request_id,d.id);any_failure=True
    ev.status='failed' if any_failure else ('processed' if created or simulations else 'processed');trace=list(ev.processing_trace or []);trace.append({'at':utcnow().isoformat(),'step':'processing','status':ev.status});ev.processing_trace=trace
    db.commit();return simulations

def _auth_headers(dest):
    h=dict(dest.headers or {})
    auth_type=dest.auth_type or 'none'
    if auth_type=='none':return h
    try:secret=decrypt(dest.auth_secret_encrypted)
    except Exception as exc:raise ValueError('Destination authentication configuration invalid') from exc
    if not secret:raise ValueError('Destination authentication secret not configured')
    if auth_type=='bearer':h['Authorization']=f'Bearer {secret}'
    elif auth_type=='api_key':h[dest.auth_header_name or 'X-API-Key']=secret
    elif auth_type=='basic':
        if not (dest.auth_username or '').strip():raise ValueError('Destination Basic Auth username not configured')
        import base64; token=base64.b64encode(f'{dest.auth_username}:{secret}'.encode()).decode();h['Authorization']=f'Basic {token}'
    elif auth_type=='custom':h[dest.auth_header_name or 'X-Webhook-Secret']=secret
    else:raise ValueError('Destination authentication type invalid')
    return h

def should_retry(dest,status,error):
    if error:return True
    return status in (dest.retry_statuses or [])

def perform_delivery(db,delivery:Delivery,dest:Destination|None=None):
    dest=dest or db.get(Destination,delivery.destination_id)
    if not dest or not dest.active:
        delivery.status='skipped';delivery.error='Destination disabled or missing';db.commit();return
    req=json.loads(decrypt(delivery.final_request_encrypted)); delivery.attempt_count+=1; attempt_no=delivery.attempt_count
    start=time.perf_counter();status=None;err='';resp_text=''
    try:
        url=req.get('url') or dest.url; method=(req.get('method') or dest.method).upper(); query=req.get('query') if isinstance(req.get('query'),dict) else (dest.query_params or {})
        validate_destination_url(url,allow_private=(settings.allow_private_destinations or dest.allow_private),allow_localhost=(settings.allow_localhost_destinations or dest.allow_localhost))
        headers=dict(req.get('headers') or {})
        headers.update(_auth_headers(dest))
        with httpx.Client(timeout=dest.timeout_seconds,verify=dest.verify_tls,follow_redirects=False) as client:
            if req.get('body_mode')=='raw':
                if req.get('body_encoding')=='base64':
                    try: raw_content=base64.b64decode(req.get('body') or '',validate=True)
                    except Exception: raw_content=b''
                else:
                    raw_content=(req.get('body') or '').encode('utf-8')
                response=client.request(method,url,headers=headers,params=query,content=raw_content)
            else:
                response=client.request(method,url,headers=headers,params=query,json=req.get('body'))
            status=response.status_code;resp_text=response.text[:200000];resp_headers=dict(getattr(response,'headers',{}))
    except Exception as e: err=str(e)
    duration=(time.perf_counter()-start)*1000
    if 'resp_headers' not in locals():resp_headers={}
    delivery.http_status=status;delivery.duration_ms=duration;delivery.error=err
    parsed_response=parse_json(resp_text) if resp_text else None
    response_obj={'status':status,'headers':resp_headers,'body':parsed_response if parsed_response is not None else resp_text,'error':err}
    delivery.response_encrypted=encrypt(json.dumps(response_obj,ensure_ascii=False));delivery.response_masked=json.dumps(mask_json(response_obj),ensure_ascii=False,indent=2)
    db.add(DeliveryAttempt(delivery_id=delivery.id,attempt_no=attempt_no,http_status=status,duration_ms=duration,error=err))
    success=status is not None and 200<=status<300 and not err
    if success:
        delivery.status='success';delivery.next_retry_at=None
    elif should_retry(dest,status,err) and attempt_no<max(1,dest.retry_attempts):
        delays=dest.retry_delays or [30]
        if dest.retry_exponential:
            # Exponential mode uses the first configured delay as its base:
            # 30, 60, 120, 240...  It must not multiply an already escalating
            # manual delay list a second time.
            delay=delays[0]*(2**(attempt_no-1))
        else:
            delay=delays[min(attempt_no-1,len(delays)-1)]
        run=utcnow()+timedelta(seconds=int(delay));delivery.status='retrying';delivery.next_retry_at=run
        db.flush();queue_job(db,'retry_delivery',{'delivery_id':delivery.id},run_at=run)
    else:
        delivery.status='failed';delivery.next_retry_at=None
    db.commit()

def _cancel_pending_retry_jobs(db, delivery_id:int):
    jobs=db.scalars(select(Job).where(Job.kind=='retry_delivery',Job.status=='queued')).all()
    for job in jobs:
        try:
            if int((job.payload or {}).get('delivery_id'))==int(delivery_id):
                job.status='cancelled'
        except (TypeError,ValueError):
            continue

def manual_retry(db,delivery_id):
    d=db.get(Delivery,delivery_id)
    if not d:return None
    _cancel_pending_retry_jobs(db,d.id)
    d.status='queued';d.next_retry_at=None;d.http_status=None;d.duration_ms=0;d.error='';d.response_encrypted='';d.response_masked=''
    db.commit();queue_job(db,'retry_delivery',{'delivery_id':d.id});return d

def clone_event(db,event,body_text=None,headers=None,query=None,method=None):
    endpoint=event.endpoint
    orig_headers=raw_headers(event)
    body=body_text.encode() if body_text is not None else event_body_bytes(event)
    q=query if query is not None else json.loads(decrypt(event.query_encrypted) or '{}')
    h=headers if headers is not None else orig_headers
    ok,msg=check_endpoint_auth(endpoint,h,body)
    ev=create_event(db,endpoint,method or event.method,event.source_ip,event.content_type,body,h,q,ok,('Replay: '+msg),replay_of_id=event.id)
    if ok:queue_job(db,'process_event',{'event_id':ev.id})
    else:ev.status='rejected';db.commit()
    return ev

def retention_cleanup(db):
    now=utcnow();
    # Endpoint-specific retention takes precedence. Failures are kept longer.
    endpoints=db.scalars(select(__import__('zentwhook.models',fromlist=['IncomingEndpoint']).IncomingEndpoint)).all()
    deleted=0
    for ep in endpoints:
        success_days=ep.retention_success_days or settings.success_retention_days
        failed_days=ep.retention_failed_days or settings.failed_retention_days
        success_cut=now-timedelta(days=success_days);failed_cut=now-timedelta(days=failed_days)
        ids=db.scalars(select(Event.id).where(Event.endpoint_id==ep.id,or_(
            (Event.status=='processed') & (Event.received_at<success_cut),
            (Event.status.in_(['failed','rejected'])) & (Event.received_at<failed_cut)
        ))).all()
        if ids:
            db.execute(delete(Event).where(Event.id.in_(ids)));deleted+=len(ids)
    db.commit();return deleted
