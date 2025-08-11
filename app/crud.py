from sqlalchemy.orm import Session
from app import models, schemas, auth
from typing import List, Optional
import re

class SensitiveDataScanner:
    """Scanner for sensitive data patterns."""
    
    SENSITIVE_PATTERNS = [
        r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # Credit card
        r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b',  # SSN
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone number
    ]
    
    @classmethod
    def contains_sensitive_data(cls, text: str) -> bool:
        """Check if text contains sensitive data."""
        for pattern in cls.SENSITIVE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

# User CRUD operations
def get_user_by_email(db: Session, email: str):
    """Get user by email."""
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    """Create new user."""
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Query CRUD operations
def create_query(db: Session, user_id: int, query: str, response: str):
    """Create new query history entry."""
    is_sensitive = SensitiveDataScanner.contains_sensitive_data(f"{query} {response}")
    
    db_query = models.QueryHistory(
        user_id=user_id,
        query=query,
        response=response,
        is_sensitive=is_sensitive
    )
    db.add(db_query)
    db.commit()
    db.refresh(db_query)
    return db_query

def get_user_queries(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    """Get user's query history."""
    return db.query(models.QueryHistory).filter(
        models.QueryHistory.user_id == user_id
    ).offset(skip).limit(limit).all()

def get_query_count(db: Session, user_id: int) -> int:
    """Get total query count for user."""
    return db.query(models.QueryHistory).filter(
        models.QueryHistory.user_id == user_id
    ).count()

# Audit log CRUD operations
def create_audit_log(
    db: Session, 
    action: str, 
    details: Optional[str] = None, 
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    severity: str = "INFO"
):
    """Create audit log entry."""
    audit_log = models.AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=ip_address,
        severity=severity
    )
    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)
    return audit_log

def get_audit_logs(db: Session, skip: int = 0, limit: int = 100):
    """Get audit logs (admin only)."""
    return db.query(models.AuditLog).offset(skip).limit(limit).all()