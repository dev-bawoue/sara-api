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
from app.schemas import Token, UserCreate
from datetime import timedelta

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

router = APIRouter(prefix="/auth/google", tags=["authentication"])

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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google authentication"
        )

@router.get("/login")
async def google_login():
    """Redirect to Google OAuth login page."""
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
    from httpx import AsyncClient
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
            id_token_str = token_data["id_token"]
            
            # Get user info from Google
            user_info = await get_google_user_info(id_token_str)
            
            # Check if user exists in database
            user = crud.get_user_by_email(db, email=user_info["email"])
            
            if not user:
                # Create new user from Google info
                user_create = UserCreate(
                    email=user_info["email"],
                    password=None  # No password for OAuth users
                )
                user = crud.create_user(db, user=user_create)
                
                # Log registration
                crud.create_audit_log(
                    db=db,
                    action="USER_REGISTRATION_GOOGLE",
                    details=f"New user registered via Google: {user_info['email']}",
                    user_id=user.id,
                    ip_address=request.client.host,
                    severity="INFO"
                )
            
            # Create access token for our API
            access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = auth.create_access_token(
                data={"sub": user.email},
                expires_delta=access_token_expires
            )
            
            return Token(access_token=access_token, token_type="bearer")
            
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate Google credentials"
        )