import base64,hashlib,hmac,json
from .security import decrypt

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
        basis=body
        if a.hmac_payload_basis=='canonical_json':
            try:basis=json.dumps(json.loads(body.decode()),sort_keys=True,separators=(',',':')).encode()
            except Exception:basis=body
        elif a.hmac_payload_basis=='utf8_text':basis=body.decode('utf-8',errors='replace').encode('utf-8')
        algo=getattr(hashlib,a.hmac_algorithm if a.hmac_algorithm in ('sha256','sha512') else 'sha256')
        expected=hmac.new(secret.encode(),basis,algo).hexdigest();given=h.get((a.header_name or 'x-signature').lower(),'');given=given.split('=',1)[-1] if '=' in given else given;ok=hmac.compare_digest(given,expected)
    else:ok=False
    return ok,('Authentication successful' if ok else 'Authentication failed')
