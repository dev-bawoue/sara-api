from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from app import schemas
from app import bigquery_crud as crud
from app.bigquery_models import User
from app.dependencies import get_current_user

router = APIRouter(prefix="/api/admin", tags=["admin"])

def get_admin_user(current_user: User = Depends(get_current_user)):
    """Verify that current user is admin."""
    if not crud.is_user_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

@router.get("/logs", response_model=List[schemas.AuditLogResponse])
async def get_audit_logs(
    skip: int = 0,
    limit: int = 50,
    admin_user: User = Depends(get_admin_user)
):
    """Get audit logs (admin only)."""
    logs = crud.get_audit_logs(skip, limit)
    
    # Convert to response format with encrypted IDs
    log_responses = []
    for log in logs:
        # Use encrypted ID if available, otherwise use a hash
        log_id = log.encrypted_id if hasattr(log, 'encrypted_id') and log.encrypted_id else str(hash(log.id))
        user_id = None
        if log.user_id:
            # For audit logs, we might want to show encrypted user IDs
            user_id = str(hash(log.user_id))
        
        log_responses.append(schemas.AuditLogResponse(
            id=log_id,
            user_id=user_id,
            action=log.action,
            details=log.details,
            ip_address=log.ip_address,
            created_at=log.created_at,
            severity=log.severity
        ))
    
    return log_responses

@router.get("/users")
async def get_all_users(
    skip: int = 0,
    limit: int = 50,
    admin_user: User = Depends(get_admin_user)
):
    """Get all users (admin only)."""
    users = crud.get_all_users(skip, limit)
    return users

@router.get("/stats")
async def get_system_stats(
    admin_user: User = Depends(get_admin_user)
):
    """Get system statistics (admin only)."""
    return crud.get_system_stats()

@router.put("/users/{user_id}/toggle")
async def toggle_user_status(
    user_id: str,
    admin_user: User = Depends(get_admin_user)
):
    """Toggle user active status (admin only)."""
    # The user_id here should be the encrypted ID from the frontend
    user = crud.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    new_status = crud.toggle_user_status(user_id)
    
    # Log action
    crud.create_audit_log(
        action="USER_STATUS_CHANGED",
        details=f"Admin {admin_user.email} {'activated' if new_status else 'deactivated'} user {user.email}",
        user_id=admin_user.id,
        severity="INFO"
    )
    
    return {"message": f"User {'activated' if new_status else 'deactivated'}", "user_id": user_id}

@router.post("/users", response_model=schemas.User)
async def create_admin_user_endpoint(
    user: schemas.UserCreate,
    admin_user: User = Depends(get_admin_user)
):
    """Create a new admin user (admin only)."""
    try:
        # Check if user already exists
        db_user = crud.get_user_by_email(email=user.email)
        if db_user:
            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )
        
        # Create new admin user
        new_user = crud.create_admin_user(user=user)
        
        # Log action
        crud.create_audit_log(
            action="ADMIN_USER_CREATED",
            details=f"Admin {admin_user.email} created new admin user: {user.email}",
            user_id=admin_user.id,
            severity="INFO"
        )
        
        # Convert to response format
        return schemas.User(
            id=new_user.encrypted_id,
            email=new_user.email,
            auth_provider=new_user.auth_provider,
            full_name=new_user.full_name,
            is_active=new_user.is_active,
            created_at=new_user.created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to create admin user"
        )