from fastapi import Request, HTTPException
from sqlalchemy.orm import Session
from .models import User
from .security import read_session

def current_user(request:Request,db:Session):
    sess=read_session(request.cookies.get('zentwhook_session'))
    if not sess:return None
    user=db.get(User,sess['user_id'])
    if not user:return None
    if int(sess.get('session_version',1))!=int(getattr(user,'session_version',1) or 1):return None
    return user

def require_user(request:Request,db:Session):
    u=current_user(request,db)
    if not u or not u.active: raise HTTPException(401,'Login required')
    return u
