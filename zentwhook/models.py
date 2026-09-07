from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import String, Text, Integer, Boolean, DateTime, ForeignKey, JSON, Float, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base

def now(): return datetime.now(timezone.utc)

class User(Base):
    __tablename__='users'
    id:Mapped[int]=mapped_column(primary_key=True)
    name:Mapped[str]=mapped_column(String(120))
    email:Mapped[str]=mapped_column(String(255),unique=True,index=True)
    password_hash:Mapped[str]=mapped_column(Text)
    role:Mapped[str]=mapped_column(String(30),default='admin')
    language:Mapped[str]=mapped_column(String(5),default='de')
    active:Mapped[bool]=mapped_column(Boolean,default=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)

class IncomingEndpoint(Base):
    __tablename__='incoming_endpoints'
    id:Mapped[int]=mapped_column(primary_key=True)
    name:Mapped[str]=mapped_column(String(160),index=True)
    description:Mapped[str]=mapped_column(Text,default='')
    slug:Mapped[str]=mapped_column(String(160),unique=True,index=True)
    active:Mapped[bool]=mapped_column(Boolean,default=True)
    methods:Mapped[list]=mapped_column(JSON,default=lambda:['POST'])
    content_types:Mapped[list]=mapped_column(JSON,default=lambda:['*/*'])
    max_payload_bytes:Mapped[int]=mapped_column(Integer,default=1048576)
    rate_limit_per_minute:Mapped[int]=mapped_column(Integer,default=120)
    request_timeout_seconds:Mapped[int]=mapped_column(Integer,default=15)
    ip_allowlist:Mapped[list]=mapped_column(JSON,default=list)
    ip_denylist:Mapped[list]=mapped_column(JSON,default=list)
    synchronous:Mapped[bool]=mapped_column(Boolean,default=False)
    retention_success_days:Mapped[int|None]=mapped_column(Integer,nullable=True)
    retention_failed_days:Mapped[int|None]=mapped_column(Integer,nullable=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    auth:Mapped['EndpointAuth']=relationship(back_populates='endpoint',uselist=False,cascade='all, delete-orphan')

class EndpointAuth(Base):
    __tablename__='endpoint_auth'
    id:Mapped[int]=mapped_column(primary_key=True)
    endpoint_id:Mapped[int]=mapped_column(ForeignKey('incoming_endpoints.id',ondelete='CASCADE'),unique=True)
    auth_type:Mapped[str]=mapped_column(String(40),default='none')
    username:Mapped[str]=mapped_column(String(255),default='')
    secret_encrypted:Mapped[str]=mapped_column(Text,default='')
    header_name:Mapped[str]=mapped_column(String(120),default='')
    hmac_algorithm:Mapped[str]=mapped_column(String(20),default='sha256')
    hmac_payload_basis:Mapped[str]=mapped_column(String(30),default='raw_body')
    endpoint:Mapped[IncomingEndpoint]=relationship(back_populates='auth')

class Event(Base):
    __tablename__='events'
    __table_args__=(Index('ix_events_endpoint_received','endpoint_id','received_at'),Index('ix_events_status_received','status','received_at'))
    id:Mapped[int]=mapped_column(primary_key=True)
    request_id:Mapped[str]=mapped_column(String(50),unique=True,index=True)
    endpoint_id:Mapped[int]=mapped_column(ForeignKey('incoming_endpoints.id',ondelete='CASCADE'),index=True)
    replay_of_id:Mapped[int|None]=mapped_column(ForeignKey('events.id',ondelete='SET NULL'),nullable=True)
    received_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,index=True)
    method:Mapped[str]=mapped_column(String(12))
    source_ip:Mapped[str]=mapped_column(String(64),index=True)
    content_type:Mapped[str]=mapped_column(String(150),default='')
    body_encrypted:Mapped[str]=mapped_column(Text,default='')
    body_masked:Mapped[str]=mapped_column(Text,default='')
    body_size:Mapped[int]=mapped_column(Integer,default=0)
    query_encrypted:Mapped[str]=mapped_column(Text,default='')
    query_masked:Mapped[dict]=mapped_column(JSON,default=dict)
    auth_ok:Mapped[bool]=mapped_column(Boolean,default=False)
    auth_message:Mapped[str]=mapped_column(String(255),default='')
    processing_ms:Mapped[float]=mapped_column(Float,default=0)
    status:Mapped[str]=mapped_column(String(30),default='queued',index=True)
    processing_trace:Mapped[list]=mapped_column(JSON,default=list)
    search_blob:Mapped[str]=mapped_column(Text,default='')
    endpoint:Mapped[IncomingEndpoint]=relationship()
    headers:Mapped[list['EventHeader']]=relationship(cascade='all, delete-orphan')


class EventHeader(Base):
    __tablename__='event_headers'
    id:Mapped[int]=mapped_column(primary_key=True)
    event_id:Mapped[int]=mapped_column(ForeignKey('events.id',ondelete='CASCADE'),index=True)
    name:Mapped[str]=mapped_column(String(180))
    masked_value:Mapped[str]=mapped_column(Text,default='')
    encrypted_value:Mapped[str]=mapped_column(Text,default='')

class Destination(Base):
    __tablename__='destinations'
    id:Mapped[int]=mapped_column(primary_key=True)
    name:Mapped[str]=mapped_column(String(160),index=True)
    description:Mapped[str]=mapped_column(Text,default='')
    active:Mapped[bool]=mapped_column(Boolean,default=True)
    kind:Mapped[str]=mapped_column(String(40),default='http')
    method:Mapped[str]=mapped_column(String(12),default='POST')
    request_mode:Mapped[str]=mapped_column(String(20),default='custom')
    url:Mapped[str]=mapped_column(Text)
    query_params:Mapped[dict]=mapped_column(JSON,default=dict)
    headers:Mapped[dict]=mapped_column(JSON,default=dict)
    auth_type:Mapped[str]=mapped_column(String(40),default='none')
    auth_username:Mapped[str]=mapped_column(String(255),default='')
    auth_secret_encrypted:Mapped[str]=mapped_column(Text,default='')
    auth_header_name:Mapped[str]=mapped_column(String(120),default='')
    timeout_seconds:Mapped[int]=mapped_column(Integer,default=15)
    verify_tls:Mapped[bool]=mapped_column(Boolean,default=True)
    retry_attempts:Mapped[int]=mapped_column(Integer,default=5)
    retry_delays:Mapped[list]=mapped_column(JSON,default=lambda:[30,120,600,1800])
    retry_exponential:Mapped[bool]=mapped_column(Boolean,default=False)
    retry_statuses:Mapped[list]=mapped_column(JSON,default=lambda:[429,500,502,503,504])
    allow_private:Mapped[bool]=mapped_column(Boolean,default=False)
    allow_localhost:Mapped[bool]=mapped_column(Boolean,default=False)
    endpoint_id:Mapped[int|None]=mapped_column(ForeignKey('incoming_endpoints.id',ondelete='CASCADE'),nullable=True,index=True)
    endpoint:Mapped[IncomingEndpoint|None]=relationship()
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)

class Flow(Base):
    __tablename__='flows'
    id:Mapped[int]=mapped_column(primary_key=True)
    name:Mapped[str]=mapped_column(String(160),index=True)
    endpoint_id:Mapped[int]=mapped_column(ForeignKey('incoming_endpoints.id',ondelete='CASCADE'),index=True)
    active:Mapped[bool]=mapped_column(Boolean,default=True)
    mode:Mapped[str]=mapped_column(String(20),default='conditional')
    condition_logic:Mapped[str]=mapped_column(String(5),default='AND')
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    endpoint:Mapped[IncomingEndpoint]=relationship()
    rules:Mapped[list['FlowRule']]=relationship(cascade='all, delete-orphan',order_by='FlowRule.position')
    mappings:Mapped[list['Mapping']]=relationship(cascade='all, delete-orphan',order_by='Mapping.position')
    routes:Mapped[list['FlowDestination']]=relationship(cascade='all, delete-orphan')

class FlowRule(Base):
    __tablename__='flow_rules'
    id:Mapped[int]=mapped_column(primary_key=True)
    flow_id:Mapped[int]=mapped_column(ForeignKey('flows.id',ondelete='CASCADE'),index=True)
    position:Mapped[int]=mapped_column(Integer,default=0)
    field_path:Mapped[str]=mapped_column(String(300))
    operator:Mapped[str]=mapped_column(String(40))
    value_json:Mapped[object|None]=mapped_column(JSON,nullable=True)

class Mapping(Base):
    __tablename__='mappings'
    id:Mapped[int]=mapped_column(primary_key=True)
    flow_id:Mapped[int]=mapped_column(ForeignKey('flows.id',ondelete='CASCADE'),index=True)
    position:Mapped[int]=mapped_column(Integer,default=0)
    target_path:Mapped[str]=mapped_column(String(300))
    source_type:Mapped[str]=mapped_column(String(30),default='field')
    source_value:Mapped[str]=mapped_column(Text,default='')
    static_type:Mapped[str]=mapped_column(String(30),default='string')
    fallback_json:Mapped[object|None]=mapped_column(JSON,nullable=True)
    transforms:Mapped[list]=mapped_column(JSON,default=list)

class FlowDestination(Base):
    __tablename__='flow_destinations'
    id:Mapped[int]=mapped_column(primary_key=True)
    flow_id:Mapped[int]=mapped_column(ForeignKey('flows.id',ondelete='CASCADE'),index=True)
    destination_id:Mapped[int]=mapped_column(ForeignKey('destinations.id',ondelete='CASCADE'),index=True)
    branch:Mapped[str]=mapped_column(String(20),default='matched')
    destination:Mapped[Destination]=relationship()
    mappings:Mapped[list['RouteMapping']]=relationship(cascade='all, delete-orphan',order_by='RouteMapping.position')

class RouteMapping(Base):
    __tablename__='route_mappings'
    id:Mapped[int]=mapped_column(primary_key=True)
    route_id:Mapped[int]=mapped_column(ForeignKey('flow_destinations.id',ondelete='CASCADE'),index=True)
    position:Mapped[int]=mapped_column(Integer,default=0)
    target_path:Mapped[str]=mapped_column(String(300))
    source_type:Mapped[str]=mapped_column(String(30),default='field')
    source_value:Mapped[str]=mapped_column(Text,default='')
    static_type:Mapped[str]=mapped_column(String(30),default='string')
    fallback_json:Mapped[object|None]=mapped_column(JSON,nullable=True)
    transforms:Mapped[list]=mapped_column(JSON,default=list)

class Delivery(Base):
    __tablename__='deliveries'
    __table_args__=(UniqueConstraint('event_id','flow_id','destination_id',name='uq_delivery_route'),Index('ix_deliveries_event_created','event_id','created_at'),Index('ix_deliveries_status_retry','status','next_retry_at'))
    id:Mapped[int]=mapped_column(primary_key=True)
    event_id:Mapped[int]=mapped_column(ForeignKey('events.id',ondelete='CASCADE'),index=True)
    flow_id:Mapped[int]=mapped_column(ForeignKey('flows.id',ondelete='SET NULL'),nullable=True)
    destination_id:Mapped[int]=mapped_column(ForeignKey('destinations.id',ondelete='SET NULL'),nullable=True,index=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,index=True)
    status:Mapped[str]=mapped_column(String(30),default='queued',index=True)
    attempt_count:Mapped[int]=mapped_column(Integer,default=0)
    next_retry_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True,index=True)
    final_request_encrypted:Mapped[str]=mapped_column(Text,default='')
    final_request_masked:Mapped[str]=mapped_column(Text,default='')
    response_encrypted:Mapped[str]=mapped_column(Text,default='')
    response_masked:Mapped[str]=mapped_column(Text,default='')
    http_status:Mapped[int|None]=mapped_column(Integer,nullable=True,index=True)
    duration_ms:Mapped[float]=mapped_column(Float,default=0)
    error:Mapped[str]=mapped_column(Text,default='')
    destination:Mapped[Destination|None]=relationship()

class DeliveryAttempt(Base):
    __tablename__='delivery_attempts'
    id:Mapped[int]=mapped_column(primary_key=True)
    delivery_id:Mapped[int]=mapped_column(ForeignKey('deliveries.id',ondelete='CASCADE'),index=True)
    attempted_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    attempt_no:Mapped[int]=mapped_column(Integer)
    http_status:Mapped[int|None]=mapped_column(Integer,nullable=True)
    duration_ms:Mapped[float]=mapped_column(Float,default=0)
    error:Mapped[str]=mapped_column(Text,default='')

class Job(Base):
    __tablename__='jobs'
    __table_args__=(Index('ix_jobs_ready','status','run_at'),)
    id:Mapped[int]=mapped_column(primary_key=True)
    kind:Mapped[str]=mapped_column(String(40),index=True)
    payload:Mapped[dict]=mapped_column(JSON,default=dict)
    status:Mapped[str]=mapped_column(String(20),default='queued',index=True)
    run_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,index=True)
    locked_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    attempts:Mapped[int]=mapped_column(Integer,default=0)
    last_error:Mapped[str]=mapped_column(Text,default='')
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)


class Setting(Base):
    __tablename__='settings'
    key:Mapped[str]=mapped_column(String(160),primary_key=True)
    value_json:Mapped[object]=mapped_column(JSON)
