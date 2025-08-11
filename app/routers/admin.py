from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app import schemas, models, crud
from app.dependencies import get_current_user

router = APIRouter(prefix="/api/admin", tags=["admin"])

# Simple admin check - in production, implement proper role-based access
ADMIN_EMAILS = ["admin@sara.com", "support@sara.com"]  # Add your admin emails

def get_admin_user(current_user: models.User = Depends(get_current_user)):
    """Verify that current user is admin."""
    if current_user.email not in ADMIN_EMAILS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

@router.get("/logs", response_model=List[schemas.AuditLogResponse])
async def get_audit_logs(
    skip: int = 0,
    limit: int = 50,
    admin_user: models.User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Get audit logs (admin only)."""
    logs = crud.get_audit_logs(db, skip, limit)
    return logs

@router.get("/users")
async def get_all_users(
    skip: int = 0,
    limit: int = 50,
    admin_user: models.User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Get all users (admin only)."""
    users = db.query(models.User).offset(skip).limit(limit).all()
    return [
        {
            "id": user.id,
            "email": user.email,
            "is_active": user.is_active,
            "created_at": user.created_at,
            "query_count": len(user.queries)
        }
        for user in users
    ]

@router.get("/stats")
async def get_system_stats(
    admin_user: models.User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Get system statistics (admin only)."""
    from datetime import date, timedelta
    
    today = date.today()
    yesterday = today - timedelta(days=1)
    week_ago = today - timedelta(days=7)
    
    # Total counts
    total_users = db.query(models.User).count()
    total_queries = db.query(models.QueryHistory).count()
    
    # Today's stats
    queries_today = db.query(models.QueryHistory).filter(
        models.QueryHistory.created_at >= today
    ).count()
    
    # Weekly stats
    queries_week = db.query(models.QueryHistory).filter(
        models.QueryHistory.created_at >= week_ago
    ).count()
    
    # Sensitive data alerts
    sensitive_queries = db.query(models.QueryHistory).filter(
        models.QueryHistory.is_sensitive == True
    ).count()
    
    # Failed login attempts (last 24h)
    failed_logins = db.query(models.AuditLog).filter(
        models.AuditLog.action == "LOGIN_FAILED",
        models.AuditLog.created_at >= yesterday
    ).count()
    
    return {
        "total_users": total_users,
        "total_queries": total_queries,
        "queries_today": queries_today,
        "queries_this_week": queries_week,
        "sensitive_queries_total": sensitive_queries,
        "failed_logins_24h": failed_logins
    }

@router.put("/users/{user_id}/toggle")
async def toggle_user_status(
    user_id: int,
    admin_user: models.User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Toggle user active status (admin only)."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.is_active = not user.is_active
    db.commit()
    
    # Log action
    crud.create_audit_log(
        db=db,
        action="USER_STATUS_CHANGED",
        details=f"Admin {admin_user.email} {'activated' if user.is_active else 'deactivated'} user {user.email}",
        user_id=admin_user.id,
        severity="INFO"
    )
    
    return {"message": f"User {'activated' if user.is_active else 'deactivated'}", "user_id": user_id}
