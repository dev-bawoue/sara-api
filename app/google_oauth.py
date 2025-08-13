from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from google.oauth2 import id_token
from google.auth.transport import requests
from jose import jwt
import os
from typing import Optional
from sqlalchemy.orm import Session
from app.database import get_db
from app import models, crud, auth
from app.schemas import Token
from datetime import timedelta
import logging

# Setup logging
logger = logging.getLogger(__name__)

# OAuth2 configuration
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl="https://oauth2.googleapis.com/token",
    scopes={
        "openid": "OpenID Connect scope",
        "email": "Access to email address",
        "profile": "Access to basic profile info"
    }
)

# Google OAuth settings
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_OAUTH_REDIRECT_URI")

router = APIRouter(prefix="/auth/google", tags=["google-oauth"])

async def get_google_user_info(token: str) -> dict:
    """Verify Google ID token and return user info."""
    try:
        idinfo = id_token.verify_oauth2_token(
            token, 
            requests.Request(), 
            GOOGLE_CLIENT_ID
        )
        
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError("Wrong issuer.")
            
        return idinfo
    except ValueError as e:
        logger.error(f"Google token verification failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google authentication"
        )

@router.get("/login")
async def google_login():
    """Redirect to Google OAuth login page."""
    if not GOOGLE_CLIENT_ID or not GOOGLE_REDIRECT_URI:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Google OAuth not configured properly"
        )
    
    from urllib.parse import urlencode
    
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent"
    }
    
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
    return {"auth_url": auth_url}

@router.get("/callback")
async def google_callback(
    request: Request,
    code: str,
    db: Session = Depends(get_db)
):
    """Handle Google OAuth callback and authenticate user."""
    if not all([GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI]):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Google OAuth not configured properly"
        )
    
    import httpx
    
    # Exchange authorization code for tokens
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            token_data = response.json()
            
            if "error" in token_data:
                logger.error(f"Google OAuth error: {token_data}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Could not authenticate with Google"
                )
            
            id_token_str = token_data.get("id_token")
            if not id_token_str:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="No ID token received from Google"
                )
            
            # Get user info from Google
            user_info = await get_google_user_info(id_token_str)
            
            # Check if user exists in database
            user = crud.get_user_by_email(db, email=user_info["email"])
            
            if not user:
                # Create new OAuth user
                user = crud.create_oauth_user(
                    db=db,
                    email=user_info["email"],
                    full_name=user_info.get("name"),
                    provider="google"
                )
                
                # Log registration
                crud.create_audit_log(
                    db=db,
                    action="USER_REGISTRATION_GOOGLE",
                    details=f"New user registered via Google: {user_info['email']}",
                    user_id=user.id,
                    ip_address=request.client.host if request.client else None,
                    severity="INFO"
                )
                
                logger.info(f"New Google user registered: {user_info['email']}")
            else:
                # Update existing user info if it's a Google OAuth user
                if user.auth_provider == "google":
                    if user_info.get("name") and user.full_name != user_info["name"]:
                        user.full_name = user_info["name"]
                    db.commit()
                elif user.auth_provider == "email":
                    # This is an existing email user - we could link accounts or require them to use email login
                    logger.warning(f"Google login attempt for existing email user: {user_info['email']}")
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="An account with this email already exists. Please login with your password."
                    )
            
            # Check if user is active
            if not user.is_active:
                logger.warning(f"Google login attempt for inactive user: {user.email}")
                crud.create_audit_log(
                    db=db,
                    action="LOGIN_FAILED_GOOGLE",
                    details=f"Google login attempt for inactive user: {user.email}",
                    user_id=user.id,
                    ip_address=request.client.host if request.client else None,
                    severity="WARNING"
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Account is inactive"
                )
            
            # Create access token for our API
            access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = auth.create_access_token(
                data={"sub": user.email},
                expires_delta=access_token_expires
            )
            
            # Log successful login
            crud.create_audit_log(
                db=db,
                action="LOGIN_SUCCESS_GOOGLE",
                details=f"User logged in via Google: {user.email}",
                user_id=user.id,
                ip_address=request.client.host if request.client else None,
                severity="INFO"
            )
            
            logger.info(f"Google user logged in successfully: {user.email}")
            
            return Token(access_token=access_token, token_type="bearer")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Google OAuth callback error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate Google credentials"
        )

@router.post("/token")
async def google_token_login(
    token_data: dict,
    request: Request,
    db: Session = Depends(get_db)
):
    """Direct Google ID token login (for frontend integration)."""
    try:
        id_token_str = token_data.get("id_token")
        if not id_token_str:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="ID token is required"
            )
        
        # Get user info from Google
        user_info = await get_google_user_info(id_token_str)
        
        # Check if user exists in database
        user = crud.get_user_by_email(db, email=user_info["email"])
        
        if not user:
            # Create new OAuth user
            user = crud.create_oauth_user(
                db=db,
                email=user_info["email"],
                full_name=user_info.get("name"),
                provider="google"
            )
            
            # Log registration
            crud.create_audit_log(
                db=db,
                action="USER_REGISTRATION_GOOGLE",
                details=f"New user registered via Google token: {user_info['email']}",
                user_id=user.id,
                ip_address=request.client.host if request.client else None,
                severity="INFO"
            )
        
        # Check if user is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is inactive"
            )
        
        # Create access token for our API
        access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = auth.create_access_token(
            data={"sub": user.email},
            expires_delta=access_token_expires
        )
        
        # Log successful login
        crud.create_audit_log(
            db=db,
            action="LOGIN_SUCCESS_GOOGLE_TOKEN",
            details=f"User logged in via Google token: {user.email}",
            user_id=user.id,
            ip_address=request.client.host if request.client else None,
            severity="INFO"
        )
        
        return Token(access_token=access_token, token_type="bearer")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Google token login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate Google token"
        )