from fastapi import Request, HTTPException
from sqlalchemy.orm import Session
from .models import User
from .security import read_session

def current_user(request:Request,db:Session):
    sess=read_session(request.cookies.get('zentwhook_session'))
    return db.get(User,sess['user_id']) if sess else None

def require_user(request:Request,db:Session):
    u=current_user(request,db)
    if not u or not u.active: raise HTTPException(401,'Login required')
    return u
