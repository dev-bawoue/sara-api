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
    """Create new user - handles both email/password and OAuth users."""
    # For OAuth users, password will be None
    hashed_password = None
    if user.password:
        hashed_password = auth.get_password_hash(user.password)
    
    db_user = models.User(
        email=user.email,
        hashed_password=hashed_password,
        auth_provider=user.auth_provider or "email",
        full_name=user.full_name
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def create_oauth_user(db: Session, email: str, full_name: str = None, provider: str = "google"):
    """Create a new OAuth user."""
    db_user = models.User(
        email=email,
        hashed_password=None,  # OAuth users don't have passwords
        auth_provider=provider,
        full_name=full_name,
        is_active=True
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Conversation CRUD operations
def create_conversation(db: Session, user_id: int, title: str):
    """Create new conversation."""
    db_conversation = models.ConversationHistory(
        user_id=user_id,
        conversation_title=title
    )
    db.add(db_conversation)
    db.commit()
    db.refresh(db_conversation)
    return db_conversation

def get_user_conversations(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    """Get user's conversations with query count."""
    conversations = db.query(models.ConversationHistory).filter(
        models.ConversationHistory.user_id == user_id,
        models.ConversationHistory.is_active == True
    ).order_by(models.ConversationHistory.updated_at.desc()).offset(skip).limit(limit).all()
    
    # Add query count to each conversation
    result = []
    for conv in conversations:
        conv_dict = {
            "id": conv.id,
            "conversation_title": conv.conversation_title,
            "created_at": conv.created_at,
            "updated_at": conv.updated_at,
            "is_active": conv.is_active,
            "query_count": len(conv.queries) if conv.queries else 0
        }
        result.append(conv_dict)
    
    return result

def get_conversation_count(db: Session, user_id: int) -> int:
    """Get total conversation count for user."""
    return db.query(models.ConversationHistory).filter(
        models.ConversationHistory.user_id == user_id,
        models.ConversationHistory.is_active == True
    ).count()

def get_conversation_queries(db: Session, conversation_id: int, skip: int = 0, limit: int = 100):
    """Get queries for a specific conversation."""
    return db.query(models.QueryHistory).filter(
        models.QueryHistory.conversation_master_id == conversation_id
    ).order_by(models.QueryHistory.created_at.asc()).offset(skip).limit(limit).all()

def update_conversation_title(db: Session, conversation_id: int, title: str):
    """Update conversation title."""
    db.query(models.ConversationHistory).filter(
        models.ConversationHistory.id == conversation_id
    ).update({
        "conversation_title": title,
        "updated_at": models.func.now()
    })
    db.commit()

def delete_conversation(db: Session, conversation_id: int, user_id: int):
    """Soft delete conversation and its queries."""
    # Soft delete conversation
    db.query(models.ConversationHistory).filter(
        models.ConversationHistory.id == conversation_id,
        models.ConversationHistory.user_id == user_id
    ).update({"is_active": False})
    
    db.commit()

# Query CRUD operations
def create_query(db: Session, user_id: int, query: str, response: str, conversation_master_id: int):
    """Create new query history entry."""
    is_sensitive = SensitiveDataScanner.contains_sensitive_data(f"{query} {response}")
    
    db_query = models.QueryHistory(
        user_id=user_id,
        query=query,
        response=response,
        conversation_master_id=conversation_master_id,
        is_sensitive=is_sensitive
    )
    db.add(db_query)
    db.commit()
    
    # Update conversation's updated_at timestamp
    db.query(models.ConversationHistory).filter(
        models.ConversationHistory.id == conversation_master_id
    ).update({"updated_at": models.func.now()})
    db.commit()
    
    db.refresh(db_query)
    return db_query

def get_user_queries(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    """Get user's query history."""
    return db.query(models.QueryHistory).filter(
        models.QueryHistory.user_id == user_id
    ).order_by(models.QueryHistory.created_at.desc()).offset(skip).limit(limit).all()

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
    return db.query(models.AuditLog).order_by(models.AuditLog.created_at.desc()).offset(skip).limit(limit).all()