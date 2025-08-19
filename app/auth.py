from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
import secrets
import time
import logging

logger = logging.getLogger(__name__)

# Password hashing - using bcrypt which is more secure
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
STATE_TOKEN_EXPIRE_MINUTES = 5  # State tokens expire in 5 minutes

# Validate SECRET_KEY
if not SECRET_KEY or SECRET_KEY == "your-secret-key-here":
    logger.warning("Using default SECRET_KEY - generate a secure key for production!")
    SECRET_KEY = "fallback-secret-key-for-development-only"

# State token storage (in production use Redis)
state_tokens = set()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against its hash."""
    try:
        if not plain_password or not hashed_password:
            logger.warning("Empty password or hash provided for verification")
            return False
        
        # Use bcrypt to verify password
        result = pwd_context.verify(plain_password, hashed_password)
        logger.debug(f"Password verification result: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def get_password_hash(password: str) -> str:
    """Generate password hash."""
    try:
        if not password:
            raise ValueError("Cannot hash empty password")
        
        hashed = pwd_context.hash(password)
        logger.debug(f"Password hashed successfully")
        return hashed
        
    except Exception as e:
        logger.error(f"Password hashing error: {e}")
        raise

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token."""
    try:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        
        logger.debug(f"JWT token created for subject: {data.get('sub')}")
        return encoded_jwt
        
    except Exception as e:
        logger.error(f"Token creation error: {e}")
        raise

def verify_token(token: str):
    """Verify JWT token and return subject."""
    try:
        if not token:
            logger.warning("Empty token provided for verification")
            return None
        
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        
        if email is None:
            logger.warning("No subject found in token")
            return None
        
        logger.debug(f"Token verified for subject: {email}")
        return email
        
    except JWTError as e:
        logger.warning(f"JWT verification failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Token verification error: {e}")
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

# Test functions for debugging (remove in production)
def test_password_operations(password: str):
    """Test password hashing and verification."""
    try:
        print(f"Original password: {password}")
        
        # Hash the password
        hashed = get_password_hash(password)
        print(f"Hashed password: {hashed}")
        
        # Verify the password
        verification_result = verify_password(password, hashed)
        print(f"Verification result: {verification_result}")
        
        # Test with wrong password
        wrong_verification = verify_password("wrongpassword", hashed)
        print(f"Wrong password verification: {wrong_verification}")
        
        return {
            "original": password,
            "hashed": hashed,
            "verification": verification_result,
            "wrong_verification": wrong_verification
        }
        
    except Exception as e:
        print(f"Test error: {e}")
        return {"error": str(e)}

if __name__ == "__main__":
    # Test the password functions
    test_result = test_password_operations("guy237")
    print("Test completed:", test_result)