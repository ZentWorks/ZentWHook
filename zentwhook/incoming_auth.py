import base64,hashlib,hmac,json,re,time
from .security import decrypt

_TEMPLATE_TOKEN_RE=re.compile(r'\{\{\s*([^{}]+?)\s*\}\}')
_DEFAULT_HMAC_TEMPLATE='{{raw_body}}'


def _canonical_json(body:bytes)->bytes:
    try:return json.dumps(json.loads(body.decode('utf-8')),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
    except Exception:return body


def _utf8_body(body:bytes)->bytes:
    return body.decode('utf-8',errors='replace').encode('utf-8')


def validate_hmac_template(template:str)->str:
    template=str(template or '').strip()
    if not template:raise ValueError('HMAC Payload-Template darf nicht leer sein')
    if len(template)>4000:raise ValueError('HMAC Payload-Template ist zu lang')
    pos=0
    for m in _TEMPLATE_TOKEN_RE.finditer(template):
        token=m.group(1).strip()
        if token in ('raw_body','utf8_body','canonical_json'):
            pass
        elif token.lower().startswith('header:'):
            name=token.split(':',1)[1].strip()
            from .validation import validate_header_name
            if not name:raise ValueError('Header-Platzhalter benötigt einen Headernamen')
            validate_header_name(name)
        else:
            raise ValueError('Unbekannter HMAC-Platzhalter: '+token)
        pos=m.end()
    # Reject leftover template-looking braces to catch typos instead of silently signing them.
    cleaned=_TEMPLATE_TOKEN_RE.sub('',template)
    if '{{' in cleaned or '}}' in cleaned:raise ValueError('Ungültiger HMAC-Platzhalter im Payload-Template')
    return template


def _render_hmac_template(template:str,headers:dict[str,str],body:bytes)->bytes:
    template=validate_hmac_template(template or _DEFAULT_HMAC_TEMPLATE)
    out=bytearray();last=0
    for m in _TEMPLATE_TOKEN_RE.finditer(template):
        out.extend(template[last:m.start()].encode('utf-8'))
        token=m.group(1).strip()
        if token=='raw_body':out.extend(body)
        elif token=='utf8_body':out.extend(_utf8_body(body))
        elif token=='canonical_json':out.extend(_canonical_json(body))
        elif token.lower().startswith('header:'):
            name=token.split(':',1)[1].strip().lower();out.extend(headers.get(name,'').encode('utf-8'))
        last=m.end()
    out.extend(template[last:].encode('utf-8'))
    return bytes(out)


def _hmac_basis(a,headers:dict[str,str],body:bytes)->bytes:
    basis=getattr(a,'hmac_payload_basis','raw_body') or 'raw_body'
    if basis=='canonical_json':return _canonical_json(body)
    if basis=='utf8_text':return _utf8_body(body)
    if basis=='custom':return _render_hmac_template(getattr(a,'hmac_payload_template','') or _DEFAULT_HMAC_TEMPLATE,headers,body)
    return body


def _timestamp_ok(a,headers:dict[str,str]):
    if not getattr(a,'hmac_verify_timestamp',False):return True,''
    name=(getattr(a,'hmac_timestamp_header','') or '').strip().lower()
    if not name:return False,'HMAC timestamp header not configured'
    raw=headers.get(name,'').strip()
    if not raw:return False,'HMAC timestamp header missing'
    try:stamp=int(raw)
    except ValueError:return False,'HMAC timestamp invalid'
    tolerance=max(1,int(getattr(a,'hmac_timestamp_tolerance_seconds',300) or 300))
    if abs(int(time.time())-stamp)>tolerance:return False,'HMAC timestamp outside allowed window'
    return True,''


def check_endpoint_auth(endpoint,headers:dict,body:bytes):
    a=endpoint.auth
    if not a or a.auth_type=='none':return True,'No authentication'
    # Header lookup is case-insensitive.
    h={str(k).lower():str(v) for k,v in headers.items()}
    secret=decrypt(a.secret_encrypted)
    if a.auth_type=='bearer':ok=hmac.compare_digest(h.get('authorization',''),f'Bearer {secret}')
    elif a.auth_type=='api_key':ok=hmac.compare_digest(h.get((a.header_name or 'x-api-key').lower(),''),secret)
    elif a.auth_type=='custom':ok=hmac.compare_digest(h.get((a.header_name or 'x-webhook-secret').lower(),''),secret)
    elif a.auth_type=='basic':
        expected='Basic '+base64.b64encode(f'{a.username}:{secret}'.encode()).decode();ok=hmac.compare_digest(h.get('authorization',''),expected)
    elif a.auth_type=='hmac':
        timestamp_ok,timestamp_message=_timestamp_ok(a,h)
        if not timestamp_ok:return False,timestamp_message
        try:basis=_hmac_basis(a,h,body)
        except ValueError:return False,'Invalid HMAC payload template'
        algo=getattr(hashlib,a.hmac_algorithm if a.hmac_algorithm in ('sha256','sha512') else 'sha256')
        expected=hmac.new(secret.encode(),basis,algo).hexdigest();given=h.get((a.header_name or 'x-signature').lower(),'').strip()
        prefix=getattr(a,'hmac_signature_prefix','') or ''
        if prefix:
            if not given.startswith(prefix):return False,'Authentication failed'
            given=given[len(prefix):]
        elif '=' in given:
            # Backward compatible with the previous tolerant handling of e.g. sha256=<digest>.
            given=given.split('=',1)[-1]
        ok=hmac.compare_digest(given,expected)
    else:ok=False
    return ok,('Authentication successful' if ok else 'Authentication failed')
