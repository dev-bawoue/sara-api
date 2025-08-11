from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import List, Optional

# User schemas
class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

# Token schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

# Query schemas
class QueryRequest(BaseModel):
    query: str

class QueryResponse(BaseModel):
    id: int
    query: str
    response: str
    created_at: datetime
    is_sensitive: bool
    
    class Config:
        from_attributes = True

# History schemas
class HistoryResponse(BaseModel):
    queries: List[QueryResponse]
    total: int

# Audit log schemas
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