from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
import secrets
import time

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
STATE_TOKEN_EXPIRE_MINUTES = 5  # State tokens expire in 5 minutes

# State token storage (in production use Redis)
state_tokens = set()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

def create_state_token() -> str:
    """Create a state token for OAuth flow."""
    token = secrets.token_urlsafe(32)
    expiry = time.time() + (STATE_TOKEN_EXPIRE_MINUTES * 60)
    state_tokens.add((token, expiry))
    return token

def verify_state_token(token: str) -> bool:
    """Verify state token and clean up expired ones."""
    current_time = time.time()
    
    # Clean up expired tokens
    global state_tokens
    state_tokens = {(t, exp) for t, exp in state_tokens if exp > current_time}
    
    # Check if token exists
    return any(t == token for t, exp in state_tokens)