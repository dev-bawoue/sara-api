from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2AuthorizationCodeBearer
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
import requests

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

async def get_google_user_info_from_access_token(access_token: str) -> dict:
    """Get user info from Google using access token (simpler approach)."""
    try:
        logger.info("Getting Google user info from access token...")
        
        # Use Google's userinfo endpoint with access token
        response = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10
        )
        
        if response.status_code != 200:
            logger.error(f"Google userinfo API error: {response.status_code} - {response.text}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to get user info from Google"
            )
        
        user_info = response.json()
        logger.info(f"Successfully got user info for: {user_info.get('email')}")
        
        # Validate required fields
        if not user_info.get('email'):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No email provided by Google"
            )
        
        return user_info
        
    except requests.RequestException as e:
        logger.error(f"Network error getting Google user info: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to connect to Google services"
        )
    except Exception as e:
        logger.error(f"Unexpected error getting Google user info: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google authentication failed"
        )

@router.get("/login")
async def google_login():
    """Initiate Google OAuth flow."""
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
    """Handle Google OAuth callback."""
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
        
        logger.info("Step 1: Exchanging authorization code for access token...")
        
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
            
            # Get access token (not ID token)
            access_token = token_data.get("access_token")
            if not access_token:
                logger.error("No access token received from Google")
                logger.error(f"Available keys in token_data: {list(token_data.keys())}")
                return RedirectResponse(
                    url=f"{FRONTEND_URL}/?error=no_access_token",
                    status_code=302
                )
            
            logger.info("Step 2: Getting user info from Google...")
            try:
                user_info = await get_google_user_info_from_access_token(access_token)
                logger.info(f"User info received: {user_info.get('email')}")
            except Exception as e:
                logger.error(f"Failed to get user info: {e}")
                return RedirectResponse(
                    url=f"{FRONTEND_URL}/?error=user_info_failed",
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
                
                logger.info("Step 4: Creating our own JWT access token...")
                
                # Create our own JWT access token (same as email/password login)
                access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
                our_access_token = auth.create_access_token(
                    data={"sub": user.email},
                    expires_delta=access_token_expires
                )
                
                logger.info(f"JWT access token created for user: {user.email}")
                
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
                
                # Redirect to frontend with our JWT token
                redirect_url = f"{FRONTEND_URL}/parents?token={our_access_token}"
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