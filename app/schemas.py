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
    id: int
    is_active: bool
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
    id: int
    conversation_title: str
    created_at: datetime
    updated_at: datetime
    is_active: bool
    query_count: int
    
    class Config:
        from_attributes = True

class QueryRequest(BaseModel):
    query: str
    conversation_master_id: Optional[int] = None

class QueryResponse(BaseModel):
    id: int
    query: str
    response: str
    conversation_master_id: int
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
    id: int
    user_id: Optional[int]
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