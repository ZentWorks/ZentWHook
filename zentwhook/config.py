from pathlib import Path
import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config=SettingsConfigDict(env_file='.env', extra='ignore')
    database_url: str = 'sqlite:///./zentwhook.db'
    app_base_url: str = 'http://localhost:8080'
    default_language: str = 'de'
    log_level: str = 'info'
    event_retention_days: int = 30
    success_retention_days: int = 14
    failed_retention_days: int = 90
    allow_private_destinations: bool = False
    allow_localhost_destinations: bool = False
    admin_email: str = ''
    admin_password: str = ''
    admin_name: str = 'Admin'
    api_token: str = ''
    data_dir: str = '/data'
    cookie_secure: bool = False

settings=Settings()
if settings.app_base_url.lower().startswith('https://'):
    settings.cookie_secure=True

def data_path(name:str)->Path:
    p=Path(settings.data_dir)
    try: p.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        p=Path('.')/'.zentwhook-data'; p.mkdir(parents=True, exist_ok=True)
    return p/name
