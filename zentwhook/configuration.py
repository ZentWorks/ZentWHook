from __future__ import annotations

import re
import secrets
from typing import Any, Literal

from fastapi import HTTPException
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .incoming_auth import validate_hmac_template
from .models import (
    Destination,
    EndpointAuth,
    Flow,
    FlowDestination,
    FlowRule,
    IncomingEndpoint,
    Mapping,
    RouteMapping,
)
from .security import decrypt, encrypt
from .ssrf import SSRFError, validate_destination_url
from .validation import (
    validate_cidrs,
    validate_content_types,
    validate_header_name,
    validate_headers,
    validate_mapping_path,
    validate_methods,
    validate_rule_operator,
    validate_slug,
)


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
            {
                "id": r.id,
                "destination_id": r.destination_id,
                "branch": r.branch,
                "mappings": [
                    {
                        "target_path": m.target_path,
                        "source_type": m.source_type,
                        "source_value": m.source_value,
                        "static_type": m.static_type,
                        "fallback": m.fallback_json,
                        "transforms": m.transforms,
                    }
                    for m in r.mappings
                ],
            }
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
    previous_auth_type = a.auth_type or "none"
    new_auth_type = payload.authentication.type
    new_secret = payload.authentication.secret or ""
    if new_auth_type != "none" and not new_secret:
        if not a.secret_encrypted or previous_auth_type != new_auth_type:
            raise HTTPException(400, "Secret ist für diese Authentifizierung erforderlich")
    if new_auth_type == "basic" and not payload.authentication.username.strip():
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
    a.auth_type = new_auth_type
    a.username = payload.authentication.username.strip()
    a.header_name = payload.authentication.header_name.strip()
    a.hmac_algorithm = payload.authentication.hmac_algorithm
    a.hmac_payload_basis = payload.authentication.hmac_payload_basis
    a.hmac_payload_template = payload.authentication.hmac_payload_template.strip() or "{{raw_body}}"
    a.hmac_signature_prefix = payload.authentication.hmac_signature_prefix
    a.hmac_verify_timestamp = payload.authentication.hmac_verify_timestamp
    a.hmac_timestamp_header = payload.authentication.hmac_timestamp_header.strip()
    a.hmac_timestamp_tolerance_seconds = payload.authentication.hmac_timestamp_tolerance_seconds
    if new_auth_type == "none":
        a.secret_encrypted = ""
        a.username = ""
    elif new_secret:
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
    previous_auth_type = d.auth_type or "none"
    if payload.auth_type != "none" and not payload.auth_secret:
        if not d.auth_secret_encrypted or previous_auth_type != payload.auth_type:
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
    if payload.auth_type == "none":
        d.auth_secret_encrypted = ""
        d.auth_username = ""
    elif payload.auth_secret:
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
        for m in route.mappings:
            try:
                validate_mapping_path(m.target_path)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
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
        db.add(route)
        db.flush()
        for pos, m in enumerate(r.mappings):
            db.add(
                RouteMapping(
                    route_id=route.id,
                    position=pos,
                    target_path=m.target_path,
                    source_type=m.source_type,
                    source_value=m.source_value,
                    static_type=m.static_type,
                    fallback_json=m.fallback,
                    transforms=m.transforms,
                )
            )


class ConfigurationImportError(ValueError):
    pass


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(value or "").strip()).strip("-_").lower()
    return slug[:120] or secrets.token_hex(4)


def _mapping_export(m) -> dict[str, Any]:
    return {
        "target": m.target_path,
        "source_type": m.source_type,
        "source": m.source_value,
        "static_type": m.static_type,
        "fallback": m.fallback_json,
        "transforms": m.transforms,
    }


def export_configuration(db: Session, *, include_secrets: bool, version: str) -> dict[str, Any]:
    endpoints = db.scalars(select(IncomingEndpoint).order_by(IncomingEndpoint.id)).all()
    destinations = db.scalars(select(Destination).order_by(Destination.id)).all()
    flows = db.scalars(select(Flow).order_by(Flow.id)).all()
    data: dict[str, Any] = {"version": version, "endpoints": [], "destinations": [], "flows": []}
    if include_secrets:
        data["contains_secrets"] = True

    for e in endpoints:
        a = e.auth
        item = {
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
            "auth_type": a.auth_type if a else "none",
            "auth_username": a.username if a else "",
            "auth_header_name": a.header_name if a else "",
            "hmac_algorithm": a.hmac_algorithm if a else "sha256",
            "hmac_payload_basis": a.hmac_payload_basis if a else "raw_body",
            "hmac_payload_template": a.hmac_payload_template if a else "{{raw_body}}",
            "hmac_signature_prefix": a.hmac_signature_prefix if a else "",
            "hmac_verify_timestamp": bool(a and a.hmac_verify_timestamp),
            "hmac_timestamp_header": a.hmac_timestamp_header if a else "",
            "hmac_timestamp_tolerance_seconds": a.hmac_timestamp_tolerance_seconds if a else 300,
        }
        if include_secrets:
            item["auth_secret"] = decrypt(a.secret_encrypted) if a and a.auth_type != "none" and a.secret_encrypted else ""
        data["endpoints"].append(item)

    for d in destinations:
        item = {
            "endpoint": d.endpoint.name if d.endpoint else None,
            "name": d.name,
            "description": d.description,
            "active": d.active,
            "request_mode": getattr(d, "request_mode", "custom"),
            "method": d.method,
            "url": d.url,
            "query_params": d.query_params,
            "headers": d.headers,
            "auth_type": d.auth_type,
            "auth_username": d.auth_username,
            "auth_header_name": d.auth_header_name,
            "timeout_seconds": d.timeout_seconds,
            "verify_tls": d.verify_tls,
            "retry_attempts": d.retry_attempts,
            "retry_delays": d.retry_delays,
            "retry_exponential": d.retry_exponential,
            "retry_statuses": d.retry_statuses,
            "allow_private": d.allow_private,
            "allow_localhost": d.allow_localhost,
        }
        if include_secrets:
            item["auth_secret"] = decrypt(d.auth_secret_encrypted) if d.auth_type != "none" and d.auth_secret_encrypted else ""
        data["destinations"].append(item)

    for f in flows:
        data["flows"].append(
            {
                "name": f.name,
                "active": f.active,
                "mode": f.mode,
                "endpoint": f.endpoint.name,
                "condition_logic": f.condition_logic,
                "rules": [
                    {"field": r.field_path, "operator": r.operator, "value": r.value_json}
                    for r in f.rules
                ],
                "mappings": [_mapping_export(m) for m in f.mappings],
                "routes": [
                    {
                        "destination": r.destination.name,
                        "branch": r.branch,
                        "mappings": [_mapping_export(m) for m in r.mappings],
                    }
                    for r in f.routes
                    if r.destination
                ],
            }
        )
    return data


def _require_list(data: dict[str, Any], key: str) -> list[Any]:
    value = data.get(key, [])
    if not isinstance(value, list):
        raise ConfigurationImportError(f"Import-Feld '{key}' muss eine Liste sein")
    if len(value) > 5000:
        raise ConfigurationImportError(f"Zu viele Einträge in '{key}'")
    return value


def _as_mapping(raw: Any, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ConfigurationImportError(f"Ungültiger Eintrag in {label}")
    return raw


def _validation_message(exc: Exception) -> str:
    if isinstance(exc, HTTPException):
        return str(exc.detail)
    if isinstance(exc, ValidationError):
        errors = exc.errors()
        if errors:
            err = errors[0]
            loc = ".".join(str(x) for x in err.get("loc", []))
            msg = err.get("msg", "Ungültiger Wert")
            return f"{loc}: {msg}" if loc else str(msg)
    return str(exc)


def _mapping_in(raw: Any) -> MappingIn:
    item = _as_mapping(raw, "Mappings")
    return MappingIn(
        target_path=item.get("target", ""),
        source_type=item.get("source_type", "field"),
        source_value=item.get("source", ""),
        static_type=item.get("static_type", "string"),
        fallback=item.get("fallback"),
        transforms=item.get("transforms", []),
    )


def import_configuration(db: Session, data: Any) -> dict[str, int]:
    if not isinstance(data, dict):
        raise ConfigurationImportError("Import-Datei muss ein JSON-Objekt enthalten")
    endpoints_in = _require_list(data, "endpoints")
    destinations_in = _require_list(data, "destinations")
    flows_in = _require_list(data, "flows")
    counts = {"endpoints": 0, "destinations": 0, "flows": 0}

    ep_by_name = {e.name: e for e in db.scalars(select(IncomingEndpoint)).all()}
    dest_by_key = {(d.endpoint_id, d.name): d for d in db.scalars(select(Destination)).all()}

    try:
        for raw in endpoints_in:
            item = _as_mapping(raw, "endpoints")
            name = item.get("name")
            if name in ep_by_name:
                continue
            slug = _safe_slug(item.get("slug") or name or "endpoint")
            base = slug
            n = 1
            while db.scalar(select(IncomingEndpoint).where(IncomingEndpoint.slug == slug)):
                n += 1
                suffix = f"-{n}"
                slug = f"{base[:120-len(suffix)]}{suffix}"
            payload = EndpointIn(
                name=name,
                description=item.get("description", ""),
                slug=slug,
                active=item.get("active", True),
                methods=item.get("methods", ["POST"]),
                content_types=item.get("content_types", ["*/*"]),
                max_payload_bytes=item.get("max_payload_bytes", 1_048_576),
                rate_limit_per_minute=item.get("rate_limit_per_minute", 120),
                request_timeout_seconds=item.get("request_timeout_seconds", 15),
                ip_allowlist=item.get("ip_allowlist", []),
                ip_denylist=item.get("ip_denylist", []),
                synchronous=item.get("synchronous", False),
                retention_success_days=item.get("retention_success_days"),
                retention_failed_days=item.get("retention_failed_days"),
                authentication=EndpointAuthIn(
                    type=item.get("auth_type", "none"),
                    username=item.get("auth_username", ""),
                    secret=item.get("auth_secret"),
                    header_name=item.get("auth_header_name", ""),
                    hmac_algorithm=item.get("hmac_algorithm", "sha256"),
                    hmac_payload_basis=item.get("hmac_payload_basis", "raw_body"),
                    hmac_payload_template=item.get("hmac_payload_template", "{{raw_body}}"),
                    hmac_signature_prefix=item.get("hmac_signature_prefix", ""),
                    hmac_verify_timestamp=item.get("hmac_verify_timestamp", False),
                    hmac_timestamp_header=item.get("hmac_timestamp_header", ""),
                    hmac_timestamp_tolerance_seconds=item.get("hmac_timestamp_tolerance_seconds", 300),
                ),
            )
            e = IncomingEndpoint()
            db.add(e)
            apply_endpoint(db, e, payload, creating=True)
            db.flush()
            ep_by_name[e.name] = e
            counts["endpoints"] += 1

        for raw in destinations_in:
            item = _as_mapping(raw, "destinations")
            endpoint_name = item.get("endpoint")
            ep = ep_by_name.get(endpoint_name)
            if not ep:
                raise ConfigurationImportError(f"Ziel '{item.get('name') or '?'}': unbekannter Webhook '{endpoint_name}'")
            name = item.get("name")
            if (ep.id, name) in dest_by_key:
                continue
            payload = DestinationIn(
                endpoint_id=ep.id,
                name=name,
                description=item.get("description", ""),
                active=item.get("active", True),
                request_mode=item.get("request_mode", "custom"),
                method=item.get("method", "POST"),
                url=item.get("url", ""),
                query_params=item.get("query_params", {}),
                headers=item.get("headers", {}),
                auth_type=item.get("auth_type", "none"),
                auth_username=item.get("auth_username", ""),
                auth_secret=item.get("auth_secret"),
                auth_header_name=item.get("auth_header_name", ""),
                timeout_seconds=item.get("timeout_seconds", 15),
                verify_tls=item.get("verify_tls", True),
                retry_attempts=item.get("retry_attempts", 5),
                retry_delays=item.get("retry_delays", [30, 120, 600, 1800]),
                retry_exponential=item.get("retry_exponential", False),
                retry_statuses=item.get("retry_statuses", [429, 500, 502, 503, 504]),
                allow_private=item.get("allow_private", False),
                allow_localhost=item.get("allow_localhost", False),
            )
            d = Destination()
            apply_destination(db, d, payload)
            db.add(d)
            db.flush()
            dest_by_key[(ep.id, d.name)] = d
            counts["destinations"] += 1

        for raw in flows_in:
            item = _as_mapping(raw, "flows")
            endpoint_name = item.get("endpoint")
            ep = ep_by_name.get(endpoint_name)
            if not ep:
                raise ConfigurationImportError(f"Flow '{item.get('name') or '?'}': unbekannter Webhook '{endpoint_name}'")
            name = item.get("name")
            if db.scalar(select(Flow).where(Flow.endpoint_id == ep.id, Flow.name == name)):
                continue
            rules_raw = _require_child_list(item, "rules", 50)
            mappings_raw = _require_child_list(item, "mappings", 100)
            routes_raw = _require_child_list(item, "routes", 50)
            routes: list[RouteIn] = []
            for route_raw in routes_raw:
                route_item = _as_mapping(route_raw, "routes")
                dest = dest_by_key.get((ep.id, route_item.get("destination")))
                if not dest:
                    raise ConfigurationImportError(
                        f"Flow '{name or '?'}': unbekanntes Ziel '{route_item.get('destination')}'"
                    )
                route_mappings = [_mapping_in(m) for m in _require_child_list(route_item, "mappings", 100)]
                routes.append(
                    RouteIn(
                        destination_id=dest.id,
                        branch=route_item.get("branch", "matched"),
                        mappings=route_mappings,
                    )
                )
            payload = FlowIn(
                name=name,
                endpoint_id=ep.id,
                active=item.get("active", True),
                mode=item.get("mode", "conditional"),
                condition_logic=item.get("condition_logic", "AND"),
                rules=[
                    FlowRuleIn(
                        field_path=_as_mapping(r, "rules").get("field", ""),
                        operator=_as_mapping(r, "rules").get("operator", "equals"),
                        value=_as_mapping(r, "rules").get("value"),
                    )
                    for r in rules_raw
                ],
                mappings=[_mapping_in(m) for m in mappings_raw],
                routes=routes,
            )
            flow = Flow(name=payload.name, endpoint_id=ep.id)
            db.add(flow)
            db.flush()
            apply_flow(db, flow, payload)
            counts["flows"] += 1
    except ConfigurationImportError:
        raise
    except (HTTPException, ValidationError, ValueError, TypeError) as exc:
        raise ConfigurationImportError(_validation_message(exc)) from exc
    return counts


def _require_child_list(item: dict[str, Any], key: str, maximum: int) -> list[Any]:
    value = item.get(key, [])
    if not isinstance(value, list):
        raise ConfigurationImportError(f"'{key}' muss eine Liste sein")
    if len(value) > maximum:
        raise ConfigurationImportError(f"Zu viele Einträge in '{key}'")
    return value
