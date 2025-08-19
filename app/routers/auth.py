from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from datetime import timedelta
import logging
from app.bigquery_database import get_bq_db
from app import schemas, auth
from app import bigquery_crud as crud
from app.bigquery_models import User
from app.dependencies import get_client_ip, get_current_user

# Add logger configuration
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["authentication"])
security = HTTPBearer()

@router.post("/register", response_model=schemas.User)
async def register(
    user: schemas.UserCreate,
    request: Request
):
    """Register new user with email and password."""
    try:
        # Validate that password is provided for email registration
        if not user.password or len(user.password.strip()) == 0:
            raise HTTPException(
                status_code=400,
                detail="Password is required for email registration"
            )
        
        # Normalize and validate email
        email = user.email.strip().lower()
        if not email:
            raise HTTPException(
                status_code=400,
                detail="Valid email is required"
            )
        
        # Check if user already exists
        db_user = crud.get_user_by_email(email=email)
        if db_user:
            logger.warning(f"Registration attempt with existing email: {email}")
            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )
        
        # Create normalized user object
        normalized_user = schemas.UserCreate(
            email=email,
            password=user.password.strip(),
            auth_provider=user.auth_provider or "email",
            full_name=user.full_name.strip() if user.full_name else None
        )
        
        # Create new user (will be assigned client role by default)
        new_user = crud.create_user(user=normalized_user)
        
        # Log registration
        crud.create_audit_log(
            action="USER_REGISTRATION",
            details=f"New user registered: {email}",
            user_id=new_user.id,
            ip_address=get_client_ip(request),
            severity="INFO"
        )
        
        logger.info(f"New user registered successfully: {email}")
        
        # Convert BigQuery model to response format with encrypted ID
        return schemas.User(
            id=new_user.encrypted_id,  # Return encrypted ID
            email=new_user.email,
            auth_provider=new_user.auth_provider,
            full_name=new_user.full_name,
            is_active=new_user.is_active,
            created_at=new_user.created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error for {user.email}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Registration failed"
        )

@router.post("/admin/register", response_model=schemas.User)
async def register_admin(
    user: schemas.UserCreate,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Register new admin user (admin only)."""
    try:
        # Check if current user is admin
        if not crud.is_user_admin(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        # Validate that password is provided
        if not user.password or len(user.password.strip()) == 0:
            raise HTTPException(
                status_code=400,
                detail="Password is required for admin registration"
            )
        
        # Normalize email
        email = user.email.strip().lower()
        
        # Check if user already exists
        db_user = crud.get_user_by_email(email=email)
        if db_user:
            logger.warning(f"Admin registration attempt with existing email: {email}")
            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )
        
        # Create normalized user object
        normalized_user = schemas.UserCreate(
            email=email,
            password=user.password.strip(),
            auth_provider=user.auth_provider or "email",
            full_name=user.full_name.strip() if user.full_name else None
        )
        
        # Create new admin user
        new_user = crud.create_admin_user(user=normalized_user)
        
        # Log registration
        crud.create_audit_log(
            action="ADMIN_USER_REGISTRATION",
            details=f"New admin user registered by {current_user.email}: {email}",
            user_id=current_user.id,
            ip_address=get_client_ip(request),
            severity="INFO"
        )
        
        logger.info(f"New admin user registered successfully: {email}")
        
        # Convert BigQuery model to response format with encrypted ID
        return schemas.User(
            id=new_user.encrypted_id,  # Return encrypted ID
            email=new_user.email,
            auth_provider=new_user.auth_provider,
            full_name=new_user.full_name,
            is_active=new_user.is_active,
            created_at=new_user.created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin registration error for {user.email}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Admin registration failed"
        )

@router.post("/login", response_model=schemas.Token)
async def login(
    user_credentials: schemas.UserLogin,
    request: Request
):
    """Authenticate user with email and password."""
    try:
        # Validate that password is provided for email login
        if not user_credentials.password or len(user_credentials.password.strip()) == 0:
            logger.warning(f"Login attempt without password for: {user_credentials.email}")
            raise HTTPException(
                status_code=400,
                detail="Password is required for email login"
            )
        
        # Normalize email
        email = user_credentials.email.strip().lower()
        password = user_credentials.password.strip()
        
        logger.info(f"Login attempt for email: {email}")
        
        # Use the new verify_user_password function
        user = crud.verify_user_password(email, password)
        
        if not user:
            # Log failed login attempt
            crud.create_audit_log(
                action="LOGIN_FAILED",
                details=f"Failed login attempt for: {email}",
                ip_address=get_client_ip(request),
                severity="WARNING"
            )
            
            logger.warning(f"Login failed for: {email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Create access token
        access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = auth.create_access_token(
            data={"sub": user.email},
            expires_delta=access_token_expires
        )
        
        # Log successful login
        crud.create_audit_log(
            action="LOGIN_SUCCESS",
            details=f"User logged in: {user.email} (provider: {user.auth_provider})",
            user_id=user.id,
            ip_address=get_client_ip(request),
            severity="INFO"
        )
        
        logger.info(f"User logged in successfully: {user.email}")
        return {
            "access_token": access_token,
            "token_type": "bearer"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error for {user_credentials.email}: {str(e)}")
        # Log the error in audit log as well
        try:
            crud.create_audit_log(
                action="LOGIN_ERROR",
                details=f"Login system error for {user_credentials.email}: {str(e)}",
                ip_address=get_client_ip(request),
                severity="ERROR"
            )
        except:
            pass  # Don't fail if audit log fails
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login system error"
        )

@router.get("/me", response_model=schemas.UserProfile)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Get current user information."""
    try:
        logger.info(f"User info requested by: {current_user.email}")
        
        # Get user's role
        role = crud.get_role_by_id(current_user.role_id)
        role_name = role.name if role else "unknown"
        
        # Convert BigQuery model to response format with encrypted ID
        return schemas.UserProfile(
            id=current_user.encrypted_id,  # Return encrypted ID
            email=current_user.email,  # Plain text email
            auth_provider=current_user.auth_provider,
            full_name=current_user.full_name,  # Plain text name
            is_active=current_user.is_active,
            created_at=current_user.created_at,
            role=role_name
        )
    except Exception as e:
        logger.error(f"Error getting user info for {current_user.email}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error retrieving user information"
        )

# Test endpoint to verify user lookup
@router.post("/test-lookup")
async def test_user_lookup(email: str):
    """Test endpoint to verify user lookup (remove in production)."""
    try:
        user = crud.get_user_by_email(email.strip().lower())
        if user:
            return {
                "found": True,
                "email": user.email,
                "id": user.id,
                "encrypted_id": user.encrypted_id,
                "has_password": bool(user.hashed_password),
                "auth_provider": user.auth_provider,
                "is_active": user.is_active
            }
        else:
            return {"found": False}
    except Exception as e:
        return {"error": str(e)}

# Test endpoint for password verification
@router.post("/test-password")
async def test_password_verify(email: str, password: str):
    """Test endpoint for password verification (remove in production)."""
    try:
        user = crud.verify_user_password(email.strip().lower(), password)
        return {
            "verified": bool(user),
            "user_found": user is not None,
            "email": user.email if user else None
        }
    except Exception as e:
        return {"error": str(e)}