from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import List, Optional

class UserBase(BaseModel):
    email: EmailStr
    auth_provider: Optional[str] = "email"
    full_name: Optional[str] = None

class UserCreate(UserBase):
    password: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: Optional[str] = None

class User(UserBase):
    id: str  # Now using encrypted ID as string
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class UserProfile(UserBase):
    id: str  # Encrypted ID
    is_active: bool
    created_at: datetime
    role: str  # User's role name (admin/client)
    
    class Config:
        from_attributes = True

class Role(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class ConversationRequest(BaseModel):
    title: str

class ConversationResponse(BaseModel):
    id: str  # Now using encrypted ID as string
    conversation_title: str
    created_at: datetime
    updated_at: datetime
    is_active: bool
    query_count: int
    
    class Config:
        from_attributes = True

class QueryRequest(BaseModel):
    query: str
    conversation_master_id: Optional[str] = None  # Now accepts encrypted ID

class QueryResponse(BaseModel):
    id: str  # Encrypted ID
    query: str
    response: str
    conversation_master_id: str  # Encrypted ID
    created_at: datetime
    is_sensitive: bool
    
    class Config:
        from_attributes = True

class HistoryResponse(BaseModel):
    queries: List[QueryResponse]
    total: int

class ConversationHistoryResponse(BaseModel):
    conversations: List[ConversationResponse]
    total: int

class AuditLogResponse(BaseModel):
    id: str  # Encrypted ID or hash
    user_id: Optional[str]  # Encrypted ID or hash
    action: str
    details: Optional[str]
    ip_address: Optional[str]
    created_at: datetime
    severity: str
    
    class Config:
        from_attributes = True

class GoogleToken(BaseModel):
    id_token: str
    access_token: str
    token_type: str
    expires_in: int

class GoogleUserInfo(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None

class SystemStatsResponse(BaseModel):
    total_users: int
    total_queries: int
    queries_today: int
    queries_this_week: int
    sensitive_queries_total: int
    failed_logins_24h: int

class UserListItem(BaseModel):
    id: str  # Encrypted ID
    email: str
    is_active: bool
    created_at: datetime
    role_name: str
    query_count: int