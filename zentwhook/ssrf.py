import ipaddress, socket
from urllib.parse import urlparse
class SSRFError(ValueError): pass

_METADATA_IPS={'169.254.169.254','100.100.100.200'}

def _validate_ip(raw,allow_private=False,allow_localhost=False):
    ip=ipaddress.ip_address(str(raw).split('%')[0])
    if str(ip) in _METADATA_IPS: raise SSRFError('Metadata-Endpunkt ist blockiert')
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local: raise SSRFError(f'Unsichere Ziel-IP blockiert: {ip}')
    if ip.is_loopback and not allow_localhost: raise SSRFError('Loopback-Ziele sind blockiert')
    if ip.is_private and not (allow_private or (ip.is_loopback and allow_localhost)): raise SSRFError('Private Netzwerkziele sind blockiert')

def validate_destination_url(url,allow_private=False,allow_localhost=False,resolve=True):
    p=urlparse(url)
    if p.scheme not in ('http','https') or not p.hostname: raise SSRFError('Nur http/https URLs sind erlaubt')
    if p.username or p.password: raise SSRFError('Credentials in URL sind nicht erlaubt')
    host=p.hostname.lower()
    if host in ('localhost','localhost.localdomain'):
        if not allow_localhost: raise SSRFError('Localhost ist blockiert')
        return True
    # Literal IPs can always be checked immediately, including metadata targets.
    try:
        literal=ipaddress.ip_address(host.split('%')[0])
    except ValueError:
        literal=None
    if literal is not None:
        _validate_ip(literal,allow_private,allow_localhost);return True
    # Configuration screens use resolve=False so temporary DNS failures do not
    # prevent saving a valid destination. Every actual delivery resolves and
    # validates again, which is the security boundary for DNS rebinding/SSRF.
    if not resolve:return True
    try: infos=socket.getaddrinfo(host,p.port or (443 if p.scheme=='https' else 80),type=socket.SOCK_STREAM)
    except socket.gaierror as e: raise SSRFError(f'DNS-Auflösung fehlgeschlagen: {e}')
    addrs={i[4][0] for i in infos}
    if not addrs: raise SSRFError('Keine Ziel-IP gefunden')
    for raw in addrs:_validate_ip(raw,allow_private,allow_localhost)
    return True
