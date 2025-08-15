from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2AuthorizationCodeBearer
from google.oauth2 import id_token
from google.auth.transport import requests
import os
from typing import Optional
from sqlalchemy.orm import Session
from app.database import get_db
from app import models, crud, auth
from app.schemas import Token
from datetime import timedelta
import logging
from urllib.parse import urlencode
import httpx
import traceback

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl="https://oauth2.googleapis.com/token",
    scopes={
        "openid": "OpenID Connect scope",
        "email": "Access to email address",
        "profile": "Access to basic profile info"
    }
)

# Environment variables
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
GOOGLE_REDIRECT_URI = f"{BACKEND_URL}/api/auth/google/callback"

# Debug: Print environment variables (remove in production)
logger.info(f"GOOGLE_CLIENT_ID: {GOOGLE_CLIENT_ID[:10] if GOOGLE_CLIENT_ID else 'Not set'}...")
logger.info(f"GOOGLE_CLIENT_SECRET: {'Set' if GOOGLE_CLIENT_SECRET else 'Not set'}")
logger.info(f"GOOGLE_REDIRECT_URI: {GOOGLE_REDIRECT_URI}")

router = APIRouter(prefix="/api/auth/google", tags=["google-oauth"])

async def get_google_user_info(token: str) -> dict:
    try:
        logger.info("Verifying Google ID token...")
        idinfo = id_token.verify_oauth2_token(
            token, 
            requests.Request(), 
            GOOGLE_CLIENT_ID
        )
        logger.info(f"Token verified for user: {idinfo.get('email')}")
        
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError("Wrong issuer.")
        return idinfo
    except ValueError as e:
        logger.error(f"Google token verification failed: {str(e)}")
        logger.error(f"Token: {token[:50]}..." if token else "No token provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Google authentication: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Unexpected error during token verification: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google authentication"
        )

@router.get("/login")
async def google_login():
    # Check configuration
    if not all([GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET]):
        logger.error("Google OAuth environment variables not set")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Google OAuth not configured properly"
        )
    
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
        "state": "state_token"
    }
    
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
    logger.info(f"Generated auth URL: {auth_url}")
    return {"auth_url": auth_url}

@router.get("/callback")
async def google_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    scope: Optional[str] = None,
    authuser: Optional[str] = None,
    prompt: Optional[str] = None,
    db: Session = Depends(get_db)
):
    try:
        logger.info("=== Google OAuth Callback Started ===")
        logger.info(f"Parameters received:")
        logger.info(f"  code: {code[:20] if code else None}...")
        logger.info(f"  state: {state}")
        logger.info(f"  error: {error}")
        logger.info(f"  scope: {scope}")
        logger.info(f"  authuser: {authuser}")
        logger.info(f"  prompt: {prompt}")
        
        # Handle OAuth errors from Google
        if error:
            logger.error(f"Google OAuth error received: {error}")
            return RedirectResponse(
                url=f"{FRONTEND_URL}/?error=google_auth_failed",
                status_code=302
            )
        
        # Check if authorization code is present
        if not code:
            logger.error("No authorization code received from Google")
            return RedirectResponse(
                url=f"{FRONTEND_URL}/?error=no_auth_code",
                status_code=302
            )
        
        # Check environment variables again
        if not all([GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET]):
            logger.error("Google OAuth not configured - missing environment variables")
            return RedirectResponse(
                url=f"{FRONTEND_URL}/?error=oauth_not_configured",
                status_code=302
            )
        
        logger.info("Step 1: Exchanging authorization code for tokens...")
        
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code"
        }
        
        logger.info(f"Token request data: {dict(data, client_secret='***')}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(token_url, data=data)
                logger.info(f"Token response status: {response.status_code}")
                logger.info(f"Token response headers: {dict(response.headers)}")
                
                response.raise_for_status()
                token_data = response.json()
                logger.info(f"Token data keys: {list(token_data.keys())}")
                
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error during token exchange: {e}")
                logger.error(f"Response content: {e.response.text}")
                return RedirectResponse(
                    url=f"{FRONTEND_URL}/?error=token_exchange_failed",
                    status_code=302
                )
            except Exception as e:
                logger.error(f"Request error during token exchange: {e}")
                return RedirectResponse(
                    url=f"{FRONTEND_URL}/?error=network_error",
                    status_code=302
                )
            
            if "error" in token_data:
                logger.error(f"Token exchange error: {token_data}")
                return RedirectResponse(
                    url=f"{FRONTEND_URL}/?error=token_exchange_error",
                    status_code=302
                )
            
            id_token_str = token_data.get("id_token")
            if not id_token_str:
                logger.error("No ID token received from Google")
                logger.error(f"Available keys in token_data: {list(token_data.keys())}")
                return RedirectResponse(
                    url=f"{FRONTEND_URL}/?error=no_id_token",
                    status_code=302
                )
            
            logger.info("Step 2: Verifying Google ID token...")
            try:
                user_info = await get_google_user_info(id_token_str)
                logger.info(f"User info received: {user_info.get('email')}")
            except Exception as e:
                logger.error(f"Token verification failed: {e}")
                return RedirectResponse(
                    url=f"{FRONTEND_URL}/?error=token_verification_failed",
                    status_code=302
                )
            
            logger.info("Step 3: Processing user in database...")
            
            # Check if user exists in database
            try:
                user = crud.get_user_by_email(db, email=user_info["email"])
                
                if not user:
                    logger.info(f"Creating new Google user: {user_info['email']}")
                    user = crud.create_oauth_user(
                        db=db,
                        email=user_info["email"],
                        full_name=user_info.get("name"),
                        provider="google"
                    )
                    logger.info(f"User created with ID: {user.id}")
                elif user.auth_provider != "google":
                    logger.warning(f"Email exists with different provider: {user_info['email']} (provider: {user.auth_provider})")
                    return RedirectResponse(
                        url=f"{FRONTEND_URL}/?error=email_exists",
                        status_code=302
                    )
                else:
                    logger.info(f"Existing Google user found: {user.email}")
                
                # Check if user is active
                if not user.is_active:
                    logger.warning(f"Inactive user attempted login: {user.email}")
                    return RedirectResponse(
                        url=f"{FRONTEND_URL}/?error=account_inactive",
                        status_code=302
                    )
                
                logger.info("Step 4: Creating access token...")
                
                # Create access token
                access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
                access_token = auth.create_access_token(
                    data={"sub": user.email},
                    expires_delta=access_token_expires
                )
                
                logger.info(f"Access token created for user: {user.email}")
                
                # Log successful login
                try:
                    crud.create_audit_log(
                        db=db,
                        action="LOGIN_SUCCESS_GOOGLE",
                        details=f"User logged in via Google: {user.email}",
                        user_id=user.id,
                        ip_address=request.client.host if request.client else None,
                        severity="INFO"
                    )
                except Exception as e:
                    logger.warning(f"Failed to create audit log: {e}")
                
                logger.info("Step 5: Redirecting to frontend...")
                
                # Redirect to frontend with token
                redirect_url = f"{FRONTEND_URL}/parents?token={access_token}"
                logger.info(f"Redirecting to: {redirect_url}")
                
                return RedirectResponse(
                    url=redirect_url,
                    status_code=302
                )
                
            except Exception as e:
                logger.error(f"Database error: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                return RedirectResponse(
                    url=f"{FRONTEND_URL}/?error=database_error",
                    status_code=302
                )
            
    except Exception as e:
        logger.error(f"Unexpected error in Google callback: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return RedirectResponse(
            url=f"{FRONTEND_URL}/?error=unexpected_error",
            status_code=302
        )

@router.post("/token")
async def google_token_login(
    token_data: dict,
    request: Request,
    db: Session = Depends(get_db)
):
    try:
        logger.info("Google token login attempt")
        
        id_token_str = token_data.get("id_token")
        if not id_token_str:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="ID token is required"
            )
        
        user_info = await get_google_user_info(id_token_str)
        user = crud.get_user_by_email(db, email=user_info["email"])
        
        if not user:
            user = crud.create_oauth_user(
                db=db,
                email=user_info["email"],
                full_name=user_info.get("name"),
                provider="google"
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is inactive"
            )
        
        access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = auth.create_access_token(
            data={"sub": user.email},
            expires_delta=access_token_expires
        )
        
        # Log successful login
        try:
            crud.create_audit_log(
                db=db,
                action="LOGIN_SUCCESS_GOOGLE_TOKEN",
                details=f"User logged in via Google token: {user.email}",
                user_id=user.id,
                ip_address=request.client.host if request.client else None,
                severity="INFO"
            )
        except Exception as e:
            logger.warning(f"Failed to create audit log: {e}")
        
        return Token(access_token=access_token, token_type="bearer")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Google token login error: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate Google token"
        )

# Health check endpoint for Google OAuth
@router.get("/health")
async def google_oauth_health():
    """Check Google OAuth configuration."""
    config_status = {
        "google_client_id": bool(GOOGLE_CLIENT_ID),
        "google_client_secret": bool(GOOGLE_CLIENT_SECRET),
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "frontend_url": FRONTEND_URL
    }
    
    is_configured = all([GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET])
    
    return {
        "status": "configured" if is_configured else "not_configured",
        "config": config_status,
        "message": "Google OAuth is properly configured" if is_configured else "Missing Google OAuth configuration"
    }