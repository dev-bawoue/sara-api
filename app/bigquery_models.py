"""
BigQuery database models
Fixed version with better ID handling and authentication
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
import uuid
import logging
from app.bigquery_database import get_bq_db

logger = logging.getLogger(__name__)

class BaseModel:
    """Base model with common functionality."""
    
    def __init__(self):
        self.id = str(uuid.uuid4())
        self.created_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary for BigQuery."""
        result = {}
        for key, value in self.__dict__.items():
            if isinstance(value, datetime):
                result[key] = value.isoformat()
            else:
                result[key] = value
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """Create model instance from dictionary."""
        instance = cls.__new__(cls)  # Create without calling __init__
        
        for key, value in data.items():
            if key.endswith('_at') and isinstance(value, str):
                # Parse datetime strings
                try:
                    if 'T' in value:
                        setattr(instance, key, datetime.fromisoformat(value.replace('Z', '+00:00')))
                    else:
                        setattr(instance, key, datetime.fromisoformat(value))
                except:
                    setattr(instance, key, value)
            else:
                setattr(instance, key, value)
        
        return instance

class Role(BaseModel):
    """Role model."""
    
    def __init__(self, name: str, description: Optional[str] = None):
        super().__init__()
        self.name = name
        self.description = description
    
    @classmethod
    def create(cls, name: str, description: Optional[str] = None):
        """Create a new role."""
        return cls(name=name, description=description)

class User(BaseModel):
    """User model with proper authentication handling."""
    
    def __init__(self, email: str, role_id: str, hashed_password: Optional[str] = None,
                 auth_provider: str = "email", full_name: Optional[str] = None,
                 avatar_url: Optional[str] = None):
        super().__init__()
        self.email = email.strip().lower()  # Always normalize email
        self.role_id = role_id
        self.hashed_password = hashed_password
        self.is_active = True
        self.auth_provider = auth_provider
        self.full_name = full_name
        self.avatar_url = avatar_url
        self._encrypted_id = None  # Cache for encrypted ID
    
    @property
    def encrypted_id(self) -> str:
        """Get encrypted ID, generating it if not cached."""
        if not self._encrypted_id:
            try:
                bq_db = get_bq_db()
                self._encrypted_id = bq_db.id_crypto.encrypt_id(self.id)
            except Exception as e:
                logger.error(f"Error encrypting ID: {e}")
                self._encrypted_id = f"enc_{self.id[:8]}"  # Fallback
        return self._encrypted_id
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for BigQuery storage."""
        result = super().to_dict()
        # Add encrypted_id to stored data
        result['encrypted_id'] = self.encrypted_id
        # Remove cached property
        if '_encrypted_id' in result:
            del result['_encrypted_id']
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """Create User from dictionary with proper handling."""
        # Create instance without calling __init__
        instance = cls.__new__(cls)
        
        # Set all attributes
        for key, value in data.items():
            if key == 'encrypted_id':
                instance._encrypted_id = value  # Cache the encrypted ID
            elif key.endswith('_at') and isinstance(value, str):
                # Parse datetime strings
                try:
                    if 'T' in value:
                        setattr(instance, key, datetime.fromisoformat(value.replace('Z', '+00:00')))
                    else:
                        setattr(instance, key, datetime.fromisoformat(value))
                except:
                    setattr(instance, key, value)
            else:
                setattr(instance, key, value)
        
        # Ensure email is normalized
        if hasattr(instance, 'email') and instance.email:
            instance.email = instance.email.strip().lower()
        
        return instance
    
    @classmethod
    def create(cls, email: str, role_id: str, hashed_password: Optional[str] = None,
               auth_provider: str = "email", full_name: Optional[str] = None,
               avatar_url: Optional[str] = None):
        """Create a new user."""
        return cls(
            email=email,
            role_id=role_id,
            hashed_password=hashed_password,
            auth_provider=auth_provider,
            full_name=full_name,
            avatar_url=avatar_url
        )

class ConversationHistory(BaseModel):
    """Conversation history model."""
    
    def __init__(self, user_id: str, conversation_title: str):
        super().__init__()
        self.user_id = user_id
        self.conversation_title = conversation_title
        self.updated_at = self.created_at
        self.is_active = True
        self._encrypted_id = None
    
    @property
    def encrypted_id(self) -> str:
        """Get encrypted ID."""
        if not self._encrypted_id:
            try:
                bq_db = get_bq_db()
                self._encrypted_id = bq_db.id_crypto.encrypt_id(self.id)
            except Exception as e:
                logger.error(f"Error encrypting conversation ID: {e}")
                self._encrypted_id = f"conv_{self.id[:8]}"
        return self._encrypted_id
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = super().to_dict()
        result['encrypted_id'] = self.encrypted_id
        if '_encrypted_id' in result:
            del result['_encrypted_id']
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """Create from dictionary."""
        instance = super().from_dict(data)
        if 'encrypted_id' in data:
            instance._encrypted_id = data['encrypted_id']
        return instance
    
    @classmethod
    def create(cls, user_id: str, conversation_title: str):
        """Create a new conversation."""
        return cls(user_id=user_id, conversation_title=conversation_title)

class QueryHistory(BaseModel):
    """Query history model."""
    
    def __init__(self, user_id: str, query: str, response: str,
                 conversation_master_id: Optional[str] = None, is_sensitive: bool = False):
        super().__init__()
        self.user_id = user_id
        self.query = query
        self.response = response
        self.conversation_master_id = conversation_master_id
        self.is_sensitive = is_sensitive
        self._encrypted_id = None
    
    @property
    def encrypted_id(self) -> str:
        """Get encrypted ID."""
        if not self._encrypted_id:
            try:
                bq_db = get_bq_db()
                self._encrypted_id = bq_db.id_crypto.encrypt_id(self.id)
            except Exception as e:
                logger.error(f"Error encrypting query ID: {e}")
                self._encrypted_id = f"query_{self.id[:8]}"
        return self._encrypted_id
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = super().to_dict()
        result['encrypted_id'] = self.encrypted_id
        if '_encrypted_id' in result:
            del result['_encrypted_id']
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """Create from dictionary."""
        instance = super().from_dict(data)
        if 'encrypted_id' in data:
            instance._encrypted_id = data['encrypted_id']
        return instance
    
    @classmethod
    def create(cls, user_id: str, query: str, response: str,
               conversation_master_id: Optional[str] = None, is_sensitive: bool = False):
        """Create a new query history entry."""
        return cls(
            user_id=user_id,
            query=query,
            response=response,
            conversation_master_id=conversation_master_id,
            is_sensitive=is_sensitive
        )

class AuditLog(BaseModel):
    """Audit log model."""
    
    def __init__(self, action: str, user_id: Optional[str] = None,
                 details: Optional[str] = None, ip_address: Optional[str] = None,
                 severity: str = "INFO"):
        super().__init__()
        self.user_id = user_id
        self.action = action
        self.details = details
        self.ip_address = ip_address
        self.severity = severity
        self._encrypted_id = None
    
    @property
    def encrypted_id(self) -> str:
        """Get encrypted ID."""
        if not self._encrypted_id:
            try:
                bq_db = get_bq_db()
                self._encrypted_id = bq_db.id_crypto.encrypt_id(self.id)
            except Exception as e:
                logger.error(f"Error encrypting audit log ID: {e}")
                self._encrypted_id = f"audit_{self.id[:8]}"
        return self._encrypted_id
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = super().to_dict()
        result['encrypted_id'] = self.encrypted_id
        if '_encrypted_id' in result:
            del result['_encrypted_id']
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """Create from dictionary."""
        instance = super().from_dict(data)
        if 'encrypted_id' in data:
            instance._encrypted_id = data['encrypted_id']
        return instance
    
    @classmethod
    def create(cls, action: str, user_id: Optional[str] = None,
               details: Optional[str] = None, ip_address: Optional[str] = None,
               severity: str = "INFO"):
        """Create a new audit log entry."""
        return cls(
            action=action,
            user_id=user_id,
            details=details,
            ip_address=ip_address,
            severity=severity
        )