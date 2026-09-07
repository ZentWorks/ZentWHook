from __future__ import annotations

import hmac
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import require_user
from ..models import (
    Delivery,
    Destination,
    EndpointAuth,
    Event,
    Flow,
    FlowDestination,
    FlowRule,
    IncomingEndpoint,
    Job,
    Mapping,
    RouteMapping,
    Setting,
)
from ..security import encrypt, require_csrf
from ..services import clone_event, manual_retry, simulate_event
from ..incoming_auth import validate_hmac_template
from ..ssrf import SSRFError, validate_destination_url
from ..validation import (
    validate_cidrs,
    validate_content_types,
    validate_header_name,
    validate_headers,
    validate_mapping_path,
    validate_methods,
    validate_rule_operator,
    validate_slug,
)

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


class EndpointAuthIn(BaseModel):
    type: Literal["none", "bearer", "api_key", "basic", "hmac", "custom"] = "none"
    username: str = ""
    secret: str | None = None
    header_name: str = ""
    hmac_algorithm: Literal["sha256", "sha512"] = "sha256"
    hmac_payload_basis: Literal["raw_body", "utf8_text", "canonical_json", "custom"] = "raw_body"
    hmac_payload_template: str = Field(default="{{raw_body}}", max_length=4000)
    hmac_signature_prefix: str = Field(default="", max_length=80)
    hmac_verify_timestamp: bool = False
    hmac_timestamp_header: str = Field(default="", max_length=120)
    hmac_timestamp_tolerance_seconds: int = Field(default=300, ge=1, le=86400)


class EndpointIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=5000)
    slug: str = Field(min_length=1, max_length=120)
    methods: list[str] = Field(default_factory=lambda: ["POST"])
    active: bool = True
    content_types: list[str] = Field(default_factory=lambda: ["*/*"])
    max_payload_bytes: int = Field(default=1_048_576, ge=1024, le=100 * 1024 * 1024)
    rate_limit_per_minute: int = Field(default=120, ge=1, le=100_000)
    request_timeout_seconds: int = Field(default=15, ge=1, le=300)
    ip_allowlist: list[str] = Field(default_factory=list)
    ip_denylist: list[str] = Field(default_factory=list)
    synchronous: bool = False
    retention_success_days: int | None = Field(default=None, ge=1, le=36_500)
    retention_failed_days: int | None = Field(default=None, ge=1, le=36_500)
    authentication: EndpointAuthIn = Field(default_factory=EndpointAuthIn)


class DestinationIn(BaseModel):
    endpoint_id: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=5000)
    method: str = "POST"
    request_mode: Literal["passthrough", "custom"] = "passthrough"
    url: str
    active: bool = True
    query_params: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, Any] = Field(default_factory=dict)
    auth_type: Literal["none", "bearer", "api_key", "basic", "custom"] = "none"
    auth_username: str = ""
    auth_secret: str | None = None
    auth_header_name: str = ""
    timeout_seconds: int = Field(default=15, ge=1, le=300)
    verify_tls: bool = True
    retry_attempts: int = Field(default=5, ge=1, le=20)
    retry_delays: list[int] = Field(default_factory=lambda: [30, 120, 600, 1800])
    retry_exponential: bool = False
    retry_statuses: list[int] = Field(default_factory=lambda: [429, 500, 502, 503, 504])
    allow_private: bool = False
    allow_localhost: bool = False


class FlowRuleIn(BaseModel):
    field_path: str = Field(min_length=1, max_length=300)
    operator: str
    value: Any = None


class MappingIn(BaseModel):
    target_path: str = Field(min_length=1, max_length=300)
    source_type: Literal["field", "static", "combine"] = "field"
    source_value: str = ""
    static_type: Literal["string", "number", "boolean", "null", "object", "array"] = "string"
    fallback: Any = None
    transforms: list[dict[str, Any]] = Field(default_factory=list)


class RouteIn(BaseModel):
    destination_id: int = Field(ge=1)
    branch: Literal["matched", "else", "always"] = "matched"
    mappings: list[MappingIn] = Field(default_factory=list, max_length=100)


class FlowIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    endpoint_id: int = Field(ge=1)
    active: bool = True
    mode: Literal["direct", "conditional"] = "conditional"
    condition_logic: Literal["AND", "OR"] = "AND"
    rules: list[FlowRuleIn] = Field(default_factory=list, max_length=50)
    mappings: list[MappingIn] = Field(default_factory=list, max_length=100)
    routes: list[RouteIn] = Field(default_factory=list, max_length=50)


def endpoint_out(e: IncomingEndpoint) -> dict[str, Any]:
    a = e.auth
    return {
        "id": e.id,
        "name": e.name,
        "description": e.description,
        "slug": e.slug,
        "active": e.active,
        "methods": e.methods,
        "content_types": e.content_types,
        "max_payload_bytes": e.max_payload_bytes,
        "rate_limit_per_minute": e.rate_limit_per_minute,
        "request_timeout_seconds": e.request_timeout_seconds,
        "ip_allowlist": e.ip_allowlist,
        "ip_denylist": e.ip_denylist,
        "synchronous": e.synchronous,
        "retention_success_days": e.retention_success_days,
        "retention_failed_days": e.retention_failed_days,
        "authentication": {
            "type": a.auth_type if a else "none",
            "username": a.username if a else "",
            "header_name": a.header_name if a else "",
            "hmac_algorithm": a.hmac_algorithm if a else "sha256",
            "hmac_payload_basis": a.hmac_payload_basis if a else "raw_body",
            "hmac_payload_template": a.hmac_payload_template if a else "{{raw_body}}",
            "hmac_signature_prefix": a.hmac_signature_prefix if a else "",
            "hmac_verify_timestamp": bool(a and a.hmac_verify_timestamp),
            "hmac_timestamp_header": a.hmac_timestamp_header if a else "",
            "hmac_timestamp_tolerance_seconds": a.hmac_timestamp_tolerance_seconds if a else 300,
            "secret_configured": bool(a and a.secret_encrypted),
        },
    }


def destination_out(d: Destination) -> dict[str, Any]:
    return {
        "id": d.id,
        "endpoint_id": d.endpoint_id,
        "name": d.name,
        "description": d.description,
        "active": d.active,
        "kind": d.kind,
        "method": d.method,
        "request_mode": getattr(d, "request_mode", "custom"),
        "url": d.url,
        "query_params": d.query_params,
        "headers": d.headers,
        "auth_type": d.auth_type,
        "auth_username": d.auth_username,
        "auth_header_name": d.auth_header_name,
        "auth_secret_configured": bool(d.auth_secret_encrypted),
        "timeout_seconds": d.timeout_seconds,
        "verify_tls": d.verify_tls,
        "retry_attempts": d.retry_attempts,
        "retry_delays": d.retry_delays,
        "retry_exponential": d.retry_exponential,
        "retry_statuses": d.retry_statuses,
        "allow_private": d.allow_private,
        "allow_localhost": d.allow_localhost,
    }


def flow_out(f: Flow) -> dict[str, Any]:
    return {
        "id": f.id,
        "name": f.name,
        "endpoint_id": f.endpoint_id,
        "active": f.active,
        "mode": f.mode,
        "condition_logic": f.condition_logic,
        "rules": [
            {"id": r.id, "field_path": r.field_path, "operator": r.operator, "value": r.value_json}
            for r in f.rules
        ],
        "mappings": [
            {
                "id": m.id,
                "target_path": m.target_path,
                "source_type": m.source_type,
                "source_value": m.source_value,
                "static_type": m.static_type,
                "fallback": m.fallback_json,
                "transforms": m.transforms,
            }
            for m in f.mappings
        ],
        "routes": [
            {"id": r.id, "destination_id": r.destination_id, "branch": r.branch, "mappings": [{"target_path": m.target_path, "source_type": m.source_type, "source_value": m.source_value, "static_type": m.static_type, "fallback": m.fallback_json, "transforms": m.transforms} for m in r.mappings]}
            for r in f.routes
        ],
    }


def apply_endpoint(db: Session, e: IncomingEndpoint, payload: EndpointIn, creating: bool = False):
    try:
        slug = validate_slug(payload.slug.strip().lower())
        methods = validate_methods(payload.methods)
        content_types = validate_content_types(payload.content_types)
        validate_cidrs(payload.ip_allowlist)
        validate_cidrs(payload.ip_denylist)
        validate_header_name(payload.authentication.header_name)
        if payload.authentication.type == "hmac":
            if payload.authentication.hmac_payload_basis == "custom":
                validate_hmac_template(payload.authentication.hmac_payload_template)
            if payload.authentication.hmac_verify_timestamp:
                validate_header_name(payload.authentication.hmac_timestamp_header)
                if not payload.authentication.hmac_timestamp_header.strip():
                    raise ValueError("Timestamp-Header ist für die HMAC Timestamp-Prüfung erforderlich")
            if "\r" in payload.authentication.hmac_signature_prefix or "\n" in payload.authentication.hmac_signature_prefix:
                raise ValueError("Ungültiges HMAC Signatur-Präfix")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    duplicate = db.scalar(select(IncomingEndpoint).where(IncomingEndpoint.slug == slug, IncomingEndpoint.id != (e.id or -1)))
    if duplicate:
        raise HTTPException(409, "Endpoint-Bezeichnung bereits vergeben")
    a = e.auth
    if creating and a is None:
        a = EndpointAuth()
        e.auth = a
    if a is None:
        a = EndpointAuth(endpoint_id=e.id)
        db.add(a)
    new_secret = payload.authentication.secret or ""
    if payload.authentication.type != "none" and not new_secret and not a.secret_encrypted:
        raise HTTPException(400, "Secret ist für diese Authentifizierung erforderlich")
    if payload.authentication.type == "basic" and not payload.authentication.username.strip():
        raise HTTPException(400, "Benutzername ist für Basic Auth erforderlich")
    e.name = payload.name.strip()
    e.description = payload.description.strip()
    e.slug = slug
    e.active = payload.active
    e.methods = methods
    e.content_types = content_types
    e.max_payload_bytes = payload.max_payload_bytes
    e.rate_limit_per_minute = payload.rate_limit_per_minute
    e.request_timeout_seconds = payload.request_timeout_seconds
    e.ip_allowlist = payload.ip_allowlist
    e.ip_denylist = payload.ip_denylist
    e.synchronous = payload.synchronous
    e.retention_success_days = payload.retention_success_days
    e.retention_failed_days = payload.retention_failed_days
    a.auth_type = payload.authentication.type
    a.username = payload.authentication.username.strip()
    a.header_name = payload.authentication.header_name.strip()
    a.hmac_algorithm = payload.authentication.hmac_algorithm
    a.hmac_payload_basis = payload.authentication.hmac_payload_basis
    a.hmac_payload_template = payload.authentication.hmac_payload_template.strip() or "{{raw_body}}"
    a.hmac_signature_prefix = payload.authentication.hmac_signature_prefix
    a.hmac_verify_timestamp = payload.authentication.hmac_verify_timestamp
    a.hmac_timestamp_header = payload.authentication.hmac_timestamp_header.strip()
    a.hmac_timestamp_tolerance_seconds = payload.authentication.hmac_timestamp_tolerance_seconds
    if new_secret:
        a.secret_encrypted = encrypt(new_secret)


def apply_destination(db: Session, d: Destination, payload: DestinationIn):
    if not db.get(IncomingEndpoint, payload.endpoint_id):
        raise HTTPException(400, "Ungültiger Endpoint")
    try:
        method = validate_methods([payload.method])[0]
        validate_destination_url(payload.url.strip(), allow_private=True, allow_localhost=True, resolve=False)
        validate_headers(payload.headers)
        validate_header_name(payload.auth_header_name)
    except (ValueError, SSRFError) as exc:
        raise HTTPException(400, str(exc)) from exc
    if payload.auth_type != "none" and not (payload.auth_secret or d.auth_secret_encrypted):
        raise HTTPException(400, "Secret ist für diese Authentifizierung erforderlich")
    if payload.auth_type == "basic" and not payload.auth_username.strip():
        raise HTTPException(400, "Benutzername ist für Basic Auth erforderlich")
    if any(x < 0 or x > 86400 for x in payload.retry_delays):
        raise HTTPException(400, "Ungültiger Retry-Delay")
    if any(x < 100 or x > 599 for x in payload.retry_statuses):
        raise HTTPException(400, "Ungültiger HTTP-Status für Retry")
    d.endpoint_id = payload.endpoint_id
    d.name = payload.name.strip()
    d.description = payload.description.strip()
    d.active = payload.active
    d.kind = "http"
    d.method = method
    d.request_mode = payload.request_mode
    d.url = payload.url.strip()
    d.query_params = payload.query_params
    d.headers = payload.headers
    d.auth_type = payload.auth_type
    d.auth_username = payload.auth_username.strip()
    d.auth_header_name = payload.auth_header_name.strip()
    if payload.auth_secret:
        d.auth_secret_encrypted = encrypt(payload.auth_secret)
    d.timeout_seconds = payload.timeout_seconds
    d.verify_tls = payload.verify_tls
    d.retry_attempts = payload.retry_attempts
    d.retry_delays = payload.retry_delays or [30]
    d.retry_exponential = payload.retry_exponential
    d.retry_statuses = payload.retry_statuses
    d.allow_private = payload.allow_private
    d.allow_localhost = payload.allow_localhost


def apply_flow(db: Session, f: Flow, payload: FlowIn):
    if not db.get(IncomingEndpoint, payload.endpoint_id):
        raise HTTPException(400, "Ungültiger Endpoint")
    for r in payload.rules:
        try:
            validate_rule_operator(r.operator)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    for m in payload.mappings:
        try:
            validate_mapping_path(m.target_path)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    for route in payload.routes:
        dest = db.get(Destination, route.destination_id)
        if not dest or dest.endpoint_id != payload.endpoint_id:
            raise HTTPException(400, f"Ungültiges Ziel für diesen Webhook: {route.destination_id}")
    f.name = payload.name.strip()
    f.endpoint_id = payload.endpoint_id
    f.active = payload.active
    f.mode = payload.mode
    f.condition_logic = payload.condition_logic
    for item in list(f.rules):
        db.delete(item)
    for item in list(f.mappings):
        db.delete(item)
    for item in list(f.routes):
        db.delete(item)
    db.flush()
    for pos, r in enumerate(payload.rules):
        db.add(FlowRule(flow_id=f.id, position=pos, field_path=r.field_path, operator=r.operator, value_json=r.value))
    for pos, m in enumerate(payload.mappings):
        db.add(
            Mapping(
                flow_id=f.id,
                position=pos,
                target_path=m.target_path,
                source_type=m.source_type,
                source_value=m.source_value,
                static_type=m.static_type,
                fallback_json=m.fallback,
                transforms=m.transforms,
            )
        )
    for r in payload.routes:
        route = FlowDestination(flow_id=f.id, destination_id=r.destination_id, branch=r.branch)
        db.add(route); db.flush()
        for pos, m in enumerate(r.mappings):
            db.add(RouteMapping(route_id=route.id, position=pos, target_path=m.target_path, source_type=m.source_type, source_value=m.source_value, static_type=m.static_type, fallback_json=m.fallback, transforms=m.transforms))


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
