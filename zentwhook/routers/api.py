from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..configuration import (
    DestinationIn,
    EndpointIn,
    FlowIn,
    apply_destination,
    apply_endpoint,
    apply_flow,
    destination_out,
    endpoint_out,
    flow_out,
)
from ..db import get_db
from ..deps import require_user
from ..models import Delivery, Destination, Event, Flow, IncomingEndpoint, Job, Setting
from ..security import require_csrf
from ..services import clone_event, manual_retry, simulate_event

router = APIRouter(prefix="/api/v1", tags=["API"])


def token_auth(request: Request) -> bool:
    token = request.headers.get("x-zentwhook-token", "")
    return bool(settings.api_token and token and hmac.compare_digest(token, settings.api_token))


def auth(request: Request, db: Session):
    if token_auth(request):
        return True
    return require_user(request, db)


def auth_write(request: Request, db: Session):
    if token_auth(request):
        return True
    require_user(request, db)
    require_csrf(request)
    return True


@router.get("/status")
def status(request: Request, db: Session = Depends(get_db)):
    auth(request, db)
    hb = db.get(Setting, "worker_heartbeat")
    return {
        "app": "ok",
        "database": "ok",
        "worker_heartbeat": hb.value_json if hb else None,
        "queued_jobs": db.scalar(select(func.count(Job.id)).where(Job.status == "queued")) or 0,
    }


@router.get("/endpoints")
def endpoints(request: Request, db: Session = Depends(get_db)):
    auth(request, db)
    return [endpoint_out(x) for x in db.scalars(select(IncomingEndpoint).order_by(IncomingEndpoint.name)).all()]


@router.get("/endpoints/{eid}")
def endpoint(eid: int, request: Request, db: Session = Depends(get_db)):
    auth(request, db)
    e = db.get(IncomingEndpoint, eid)
    if not e:
        raise HTTPException(404)
    return endpoint_out(e)


@router.post("/endpoints", status_code=201)
def create_endpoint(payload: EndpointIn, request: Request, db: Session = Depends(get_db)):
    auth_write(request, db)
    e = IncomingEndpoint()
    db.add(e)
    apply_endpoint(db, e, payload, creating=True)
    db.commit()
    db.refresh(e)
    return endpoint_out(e)


@router.put("/endpoints/{eid}")
def update_endpoint(eid: int, payload: EndpointIn, request: Request, db: Session = Depends(get_db)):
    auth_write(request, db)
    e = db.get(IncomingEndpoint, eid)
    if not e:
        raise HTTPException(404)
    apply_endpoint(db, e, payload)
    db.commit()
    db.refresh(e)
    return endpoint_out(e)


@router.delete("/endpoints/{eid}", status_code=204)
def delete_endpoint(eid: int, request: Request, db: Session = Depends(get_db)):
    auth_write(request, db)
    e = db.get(IncomingEndpoint, eid)
    if not e:
        raise HTTPException(404)
    db.delete(e)
    db.commit()


@router.get("/events")
def events(request: Request, limit: int = 50, db: Session = Depends(get_db)):
    auth(request, db)
    limit = max(1, min(200, limit))
    return [
        {
            "id": e.id,
            "request_id": e.request_id,
            "endpoint_id": e.endpoint_id,
            "received_at": e.received_at,
            "status": e.status,
            "source_ip": e.source_ip,
        }
        for e in db.scalars(select(Event).order_by(Event.received_at.desc()).limit(limit)).all()
    ]


@router.get("/events/{eid}")
def event(eid: int, request: Request, db: Session = Depends(get_db)):
    auth(request, db)
    e = db.get(Event, eid)
    if not e:
        raise HTTPException(404)
    return {
        "id": e.id,
        "request_id": e.request_id,
        "endpoint_id": e.endpoint_id,
        "received_at": e.received_at,
        "method": e.method,
        "source_ip": e.source_ip,
        "content_type": e.content_type,
        "payload_masked": e.body_masked,
        "query_masked": e.query_masked,
        "headers_masked": {h.name: h.masked_value for h in e.headers},
        "auth_ok": e.auth_ok,
        "auth_message": e.auth_message,
        "status": e.status,
        "processing_trace": e.processing_trace,
    }


@router.post("/events/{eid}/replay", status_code=202)
def replay(eid: int, request: Request, db: Session = Depends(get_db)):
    auth_write(request, db)
    e = db.get(Event, eid)
    if not e:
        raise HTTPException(404)
    n = clone_event(db, e)
    return {"event_id": n.id, "request_id": n.request_id, "status": n.status}


@router.post("/events/{eid}/dry-run")
def dry_run(eid: int, request: Request, db: Session = Depends(get_db)):
    auth_write(request, db)
    e = db.get(Event, eid)
    if not e:
        raise HTTPException(404)
    return {"event_id": e.id, "request_id": e.request_id, "results": simulate_event(db, e)}


@router.get("/destinations")
def destinations(request: Request, db: Session = Depends(get_db)):
    auth(request, db)
    return [destination_out(d) for d in db.scalars(select(Destination).order_by(Destination.name)).all()]


@router.get("/destinations/{did}")
def destination(did: int, request: Request, db: Session = Depends(get_db)):
    auth(request, db)
    d = db.get(Destination, did)
    if not d:
        raise HTTPException(404)
    return destination_out(d)


@router.post("/destinations", status_code=201)
def create_destination(payload: DestinationIn, request: Request, db: Session = Depends(get_db)):
    auth_write(request, db)
    d = Destination()
    apply_destination(db, d, payload)
    db.add(d)
    db.commit()
    db.refresh(d)
    return destination_out(d)


@router.put("/destinations/{did}")
def update_destination(did: int, payload: DestinationIn, request: Request, db: Session = Depends(get_db)):
    auth_write(request, db)
    d = db.get(Destination, did)
    if not d:
        raise HTTPException(404)
    apply_destination(db, d, payload)
    db.commit()
    db.refresh(d)
    return destination_out(d)


@router.delete("/destinations/{did}", status_code=204)
def delete_destination(did: int, request: Request, db: Session = Depends(get_db)):
    auth_write(request, db)
    d = db.get(Destination, did)
    if not d:
        raise HTTPException(404)
    db.delete(d)
    db.commit()


@router.get("/flows")
def flows(request: Request, db: Session = Depends(get_db)):
    auth(request, db)
    return [flow_out(f) for f in db.scalars(select(Flow).order_by(Flow.name)).all()]


@router.get("/flows/{fid}")
def flow(fid: int, request: Request, db: Session = Depends(get_db)):
    auth(request, db)
    f = db.get(Flow, fid)
    if not f:
        raise HTTPException(404)
    return flow_out(f)


@router.post("/flows", status_code=201)
def create_flow(payload: FlowIn, request: Request, db: Session = Depends(get_db)):
    auth_write(request, db)
    f = Flow(name=payload.name, endpoint_id=payload.endpoint_id)
    db.add(f)
    db.flush()
    apply_flow(db, f, payload)
    db.commit()
    db.refresh(f)
    return flow_out(f)


@router.put("/flows/{fid}")
def update_flow(fid: int, payload: FlowIn, request: Request, db: Session = Depends(get_db)):
    auth_write(request, db)
    f = db.get(Flow, fid)
    if not f:
        raise HTTPException(404)
    apply_flow(db, f, payload)
    db.commit()
    db.refresh(f)
    return flow_out(f)


@router.delete("/flows/{fid}", status_code=204)
def delete_flow(fid: int, request: Request, db: Session = Depends(get_db)):
    auth_write(request, db)
    f = db.get(Flow, fid)
    if not f:
        raise HTTPException(404)
    db.delete(f)
    db.commit()


@router.get("/deliveries")
def deliveries(request: Request, limit: int = 50, db: Session = Depends(get_db)):
    auth(request, db)
    limit = max(1, min(200, limit))
    return [
        {
            "id": d.id,
            "event_id": d.event_id,
            "destination_id": d.destination_id,
            "status": d.status,
            "http_status": d.http_status,
            "attempt_count": d.attempt_count,
            "next_retry_at": d.next_retry_at,
        }
        for d in db.scalars(select(Delivery).order_by(Delivery.created_at.desc()).limit(limit)).all()
    ]


@router.get("/deliveries/{did}")
def delivery(did: int, request: Request, db: Session = Depends(get_db)):
    auth(request, db)
    d = db.get(Delivery, did)
    if not d:
        raise HTTPException(404)
    return {
        "id": d.id,
        "event_id": d.event_id,
        "flow_id": d.flow_id,
        "destination_id": d.destination_id,
        "created_at": d.created_at,
        "status": d.status,
        "http_status": d.http_status,
        "attempt_count": d.attempt_count,
        "next_retry_at": d.next_retry_at,
        "duration_ms": d.duration_ms,
        "error": d.error,
        "request_masked": d.final_request_masked,
        "response_masked": d.response_masked,
    }


@router.post("/deliveries/{did}/retry", status_code=202)
def retry(did: int, request: Request, db: Session = Depends(get_db)):
    auth_write(request, db)
    d = manual_retry(db, did)
    if not d:
        raise HTTPException(404)
    return {"delivery_id": d.id, "status": "queued"}
