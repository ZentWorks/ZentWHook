import base64, os, secrets
from pathlib import Path
from .config import data_path, settings

def ensure(name, nbytes=32):
    p=data_path(name)
    if not p.exists():
        value=base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).decode().encode()
        try:
            fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as f:f.write(value)
        except FileExistsError:pass
    return p

def main():
    ensure('encryption.key'); ensure('session.key')
if __name__=='__main__': main()
