import ipaddress,re
HEADER_RE=re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
SLUG_RE=re.compile(r'^[a-z0-9][a-z0-9_-]{0,119}$')
PATH_RE=re.compile(r'^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+|\[\d+\])*$')

MIME_TOKEN_RE=re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

def normalize_content_type(value):
    return str(value or '').split(';',1)[0].strip().lower()

def validate_content_type_pattern(value):
    v=normalize_content_type(value)
    if not v or '\r' in str(value) or '\n' in str(value) or '/' not in v:
        raise ValueError('Ungültiger Content-Type: '+str(value))
    major,minor=v.split('/',1)
    if major=='*' and minor!='*':
        raise ValueError('Ungültiger Content-Type: '+str(value))
    if major!='*' and not MIME_TOKEN_RE.fullmatch(major):
        raise ValueError('Ungültiger Content-Type: '+str(value))
    if minor=='*':
        return v
    if minor.startswith('*+'):
        suffix=minor[2:]
        if not suffix or not MIME_TOKEN_RE.fullmatch(suffix):
            raise ValueError('Ungültiger Content-Type: '+str(value))
        return v
    if '*' in minor or not MIME_TOKEN_RE.fullmatch(minor):
        raise ValueError('Ungültiger Content-Type: '+str(value))
    return v

def content_type_allowed(actual,allowed):
    ct=normalize_content_type(actual)
    if not ct:
        return False
    if '/' not in ct:
        return False
    major,minor=ct.split('/',1)
    for raw in allowed or []:
        pattern=normalize_content_type(raw)
        if pattern=='*/*':
            return True
        if '/' not in pattern:
            continue
        pmajor,pminor=pattern.split('/',1)
        if pmajor!=major:
            continue
        if pminor=='*' or pminor==minor:
            return True
        if pminor.startswith('*+') and minor.endswith('+'+pminor[2:]):
            return True
    return False

def validate_cidrs(values):
    bad=[]
    for v in values:
        try:ipaddress.ip_network(v,strict=False)
        except ValueError:bad.append(v)
    if bad:raise ValueError('Ungültige IP/CIDR: '+', '.join(bad))
    return values

def validate_header_name(name):
    if name and not HEADER_RE.fullmatch(name):raise ValueError('Ungültiger Headername: '+name)
    return name

def validate_headers(headers,allow_sensitive=False):
    sensitive={'authorization','proxy-authorization','cookie','set-cookie','x-api-key','x-auth-token'}
    for k,v in headers.items():
        if not allow_sensitive and k.lower() in sensitive:raise ValueError('Sensitiven Header bitte über Authentifizierung konfigurieren: '+k)
        validate_header_name(k)
        if '\r' in str(v) or '\n' in str(v):raise ValueError('Header-Wert enthält Zeilenumbruch: '+k)
    return headers

def validate_mapping_path(path):
    if not PATH_RE.fullmatch(path):raise ValueError('Ungültiger Mapping-Pfad: '+path)
    return path

VALID_METHODS={'GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'}
VALID_RULE_OPERATORS={'equals','not_equals','contains','not_contains','starts_with','ends_with','exists','not_exists','gt','lt','gte','lte','true','false','empty','not_empty'}

def validate_method(method):
    m=str(method).upper()
    if m not in VALID_METHODS:raise ValueError('Ungültige HTTP-Methode: '+m)
    return m

def validate_methods(methods):
    if not methods:raise ValueError('Mindestens eine HTTP-Methode erforderlich')
    return [validate_method(m) for m in methods]

def validate_slug(slug):
    if not SLUG_RE.fullmatch(str(slug)):raise ValueError('Ungültige Endpoint-Bezeichnung')
    return slug

def validate_content_types(values):
    if not values:raise ValueError('Mindestens ein Content-Type erforderlich')
    return [validate_content_type_pattern(v) for v in values]

def validate_rule_operator(op):
    if op not in VALID_RULE_OPERATORS:raise ValueError('Ungültiger Regel-Operator: '+str(op))
    return op
