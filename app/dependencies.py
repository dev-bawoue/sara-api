from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.database import get_db
from app import models, auth, crud
from typing import Optional

security = HTTPBearer()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Get current authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token = credentials.credentials
    email = auth.verify_token(token)
    if email is None:
        raise credentials_exception
    
    user = crud.get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception
    
    return user

def get_client_ip(request: Request) -> str:
    """Extract client IP address."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host

def log_action(
    action: str,
    details: Optional[str] = None,
    severity: str = "INFO"
):
    """Decorator to log actions."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Get dependencies from kwargs
            request = kwargs.get('request')
            db = kwargs.get('db')
            current_user = kwargs.get('current_user')
            
            ip_address = get_client_ip(request) if request else None
            user_id = current_user.id if current_user else None
            
            try:
                result = await func(*args, **kwargs)
                
                # Log successful action
                if db:
                    crud.create_audit_log(
                        db=db,
                        action=action,
                        details=details,
                        user_id=user_id,
                        ip_address=ip_address,
                        severity=severity
                    )
                
                return result
                
            except Exception as e:
                # Log failed action
                if db:
                    crud.create_audit_log(
                        db=db,
                        action=f"{action}_FAILED",
                        details=f"{details} - Error: {str(e)}",
                        user_id=user_id,
                        ip_address=ip_address,
                        severity="ERROR"
                    )
                raise
        
        return wrapper
    return decorator