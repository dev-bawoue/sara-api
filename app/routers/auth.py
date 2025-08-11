from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from datetime import timedelta
from app.database import get_db
from app import schemas, crud, auth, models
from app.dependencies import get_client_ip, get_current_user

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
        
        # Convert to Pydantic model before returning
        return schemas.User.from_orm(new_user)
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error during registration"
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
            db=db,
            action="LOGIN_SUCCESS",
            details=f"User logged in: {user.email}",
            user_id=user.id,
            ip_address=get_client_ip(request),
            severity="INFO"
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer"
        }
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error during login"
        )

@router.get("/me", response_model=schemas.User)
async def get_current_user_info(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current user information."""
    try:
        return schemas.User.from_orm(current_user)
    except Exception as e:
        logger.error(f"Error getting user info: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error retrieving user information"
        )
    