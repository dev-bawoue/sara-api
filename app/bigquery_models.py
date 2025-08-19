"""
BigQuery data models for SARA API
Updated with role-based access control and ID encryption
"""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict
import uuid

@dataclass
class Role:
    """Role model for BigQuery"""
    id: str
    name: str
    description: Optional[str]
    created_at: datetime
    
    @classmethod
    def create(cls, name: str, description: Optional[str] = None) -> 'Role':
        """Create a new role instance"""
        return cls(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            created_at=datetime.now(timezone.utc)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for BigQuery insertion"""
        data = asdict(self)
        # Convert datetime to string
        if isinstance(data['created_at'], datetime):
            data['created_at'] = data['created_at'].isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Role':
        """Create Role from BigQuery result dictionary"""
        # Convert ISO string back to datetime if needed
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
        
        return cls(**data)

@dataclass
class User:
    """User model for BigQuery with role support"""
    id: str
    encrypted_id: str
    email: str
    hashed_password: Optional[str]
    is_active: bool
    created_at: datetime
    auth_provider: str = "email"
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    role_id: str = None
    
    @classmethod
    def create(cls, email: str, role_id: str, hashed_password: Optional[str] = None, 
               auth_provider: str = "email", full_name: Optional[str] = None,
               avatar_url: Optional[str] = None, encrypted_id: str = None) -> 'User':
        """Create a new user instance"""
        user_id = str(uuid.uuid4())
        return cls(
            id=user_id,
            encrypted_id=encrypted_id or f"enc_{user_id[:8]}",  # Will be properly encrypted in database layer
            email=email,
            hashed_password=hashed_password,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            auth_provider=auth_provider,
            full_name=full_name,
            avatar_url=avatar_url,
            role_id=role_id
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for BigQuery insertion"""
        data = asdict(self)
        # Convert datetime to string
        if isinstance(data['created_at'], datetime):
            data['created_at'] = data['created_at'].isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create User from BigQuery result dictionary"""
        # Convert ISO string back to datetime if needed
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
        
        return cls(**data)

@dataclass
class ConversationHistory:
    """Conversation history model for BigQuery with encrypted ID"""
    id: str
    encrypted_id: str
    user_id: str
    conversation_title: str
    created_at: datetime
    updated_at: datetime
    is_active: bool = True
    
    @classmethod
    def create(cls, user_id: str, conversation_title: str, encrypted_id: str = None) -> 'ConversationHistory':
        """Create a new conversation instance"""
        now = datetime.now(timezone.utc)
        conv_id = str(uuid.uuid4())
        return cls(
            id=conv_id,
            encrypted_id=encrypted_id or f"enc_{conv_id[:8]}",  # Will be properly encrypted in database layer
            user_id=user_id,
            conversation_title=conversation_title,
            created_at=now,
            updated_at=now,
            is_active=True
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for BigQuery insertion"""
        data = asdict(self)
        # Convert datetime to string
        for field in ['created_at', 'updated_at']:
            if isinstance(data[field], datetime):
                data[field] = data[field].isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConversationHistory':
        """Create ConversationHistory from BigQuery result dictionary"""
        # Convert ISO strings back to datetime if needed
        for field in ['created_at', 'updated_at']:
            if isinstance(data.get(field), str):
                data[field] = datetime.fromisoformat(data[field].replace('Z', '+00:00'))
        
        return cls(**data)

@dataclass
class QueryHistory:
    """Query history model for BigQuery with encrypted ID"""
    id: str
    encrypted_id: str
    user_id: str
    query: str
    response: str
    created_at: datetime
    conversation_master_id: Optional[str] = None
    is_sensitive: bool = False
    
    @classmethod
    def create(cls, user_id: str, query: str, response: str, 
               conversation_master_id: Optional[str] = None,
               is_sensitive: bool = False, encrypted_id: str = None) -> 'QueryHistory':
        """Create a new query history instance"""
        query_id = str(uuid.uuid4())
        return cls(
            id=query_id,
            encrypted_id=encrypted_id or f"enc_{query_id[:8]}",  # Will be properly encrypted in database layer
            user_id=user_id,
            query=query,
            response=response,
            created_at=datetime.now(timezone.utc),
            conversation_master_id=conversation_master_id,
            is_sensitive=is_sensitive
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for BigQuery insertion"""
        data = asdict(self)
        # Convert datetime to string
        if isinstance(data['created_at'], datetime):
            data['created_at'] = data['created_at'].isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'QueryHistory':
        """Create QueryHistory from BigQuery result dictionary"""
        # Convert ISO string back to datetime if needed
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
        
        return cls(**data)

@dataclass
class AuditLog:
    """Audit log model for BigQuery with encrypted ID"""
    id: str
    encrypted_id: str
    action: str
    created_at: datetime
    severity: str = "INFO"
    user_id: Optional[str] = None
    details: Optional[str] = None
    ip_address: Optional[str] = None
    
    @classmethod
    def create(cls, action: str, user_id: Optional[str] = None,
               details: Optional[str] = None, ip_address: Optional[str] = None,
               severity: str = "INFO", encrypted_id: str = None) -> 'AuditLog':
        """Create a new audit log instance"""
        log_id = str(uuid.uuid4())
        return cls(
            id=log_id,
            encrypted_id=encrypted_id or f"enc_{log_id[:8]}",  # Will be properly encrypted in database layer
            action=action,
            created_at=datetime.now(timezone.utc),
            severity=severity,
            user_id=user_id,
            details=details,
            ip_address=ip_address
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for BigQuery insertion"""
        data = asdict(self)
        # Convert datetime to string
        if isinstance(data['created_at'], datetime):
            data['created_at'] = data['created_at'].isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditLog':
        """Create AuditLog from BigQuery result dictionary"""
        # Convert ISO string back to datetime if needed
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
        
        return cls(**data)

# Model registry for easy access
MODEL_REGISTRY = {
    'roles': Role,
    'users': User,
    'conversation_history': ConversationHistory,
    'query_history': QueryHistory,
    'audit_logs': AuditLog
}

def get_model_class(table_name: str):
    """Get model class for a table name"""
    return MODEL_REGISTRY.get(table_name)