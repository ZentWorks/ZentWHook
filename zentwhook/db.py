from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from .config import settings
kwargs={'pool_pre_ping':True}
if settings.database_url.startswith('sqlite'):
    kwargs['connect_args']={'check_same_thread':False}
engine=create_engine(settings.database_url, **kwargs)
SessionLocal=sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
class Base(DeclarativeBase): pass

def get_db():
    db=SessionLocal()
    try: yield db
    finally: db.close()
