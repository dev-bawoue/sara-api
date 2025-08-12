from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from datetime import timedelta
import logging
from app.database import get_db
from app import schemas, crud, auth, models
from app.dependencies import get_client_ip, get_current_user

# Add logger configuration
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["authentication"])
security = HTTPBearer()

@router.post("/register", response_model=schemas.User)
async def register(
    user: schemas.UserCreate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Register new user."""
    try:
        # Check if user already exists
        db_user = crud.get_user_by_email(db, email=user.email)
        if db_user:
            logger.warning(f"Registration attempt with existing email: {user.email}")
            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )
        
        # Create new user
        new_user = crud.create_user(db=db, user=user)
        
        # Log registration
        crud.create_audit_log(
            db=db,
            action="USER_REGISTRATION",
            details=f"New user registered: {user.email}",
            user_id=new_user.id,
            ip_address=get_client_ip(request),
            severity="INFO"
        )
        
        logger.info(f"New user registered successfully: {user.email}")
        return new_user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error for {user.email}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Registration failed"
        )

@router.post("/login", response_model=schemas.Token)
async def login(
    user_credentials: schemas.UserLogin,
    request: Request,
    db: Session = Depends(get_db)
):
    """Authenticate user and return token."""
    try:
        user = auth.authenticate_user(
            db, 
            user_credentials.email, 
            user_credentials.password
        )
        
        if not user:
            # Log failed login attempt
            crud.create_audit_log(
                db=db,
                action="LOGIN_FAILED",
                details=f"Failed login attempt for: {user_credentials.email}",
                ip_address=get_client_ip(request),
                severity="WARNING"
            )
            
            logger.warning(f"Failed login attempt for: {user_credentials.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check if user is active
        if not user.is_active:
            logger.warning(f"Login attempt for inactive user: {user.email}")
            crud.create_audit_log(
                db=db,
                action="LOGIN_FAILED",
                details=f"Login attempt for inactive user: {user.email}",
                ip_address=get_client_ip(request),
                severity="WARNING"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is inactive",
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
            db=db,
            action="LOGIN_SUCCESS",
            details=f"User logged in: {user.email}",
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
                db=db,
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

@router.get("/me", response_model=schemas.User)
async def get_current_user_info(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current user information."""
    try:
        logger.info(f"User info requested by: {current_user.email}")
        return current_user
    except Exception as e:
        logger.error(f"Error getting user info for {current_user.email}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error retrieving user information"
        )