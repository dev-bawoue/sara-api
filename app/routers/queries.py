from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List
import google.generativeai as genai
import os
from app.database import get_db
from app import schemas, models, crud
from app.dependencies import get_current_user, get_client_ip

# Configure Gemini API
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash")

router = APIRouter(prefix="/api", tags=["queries"])

class LLMProxy:
    """Proxy for LLM with quota and safety checks."""
    
    MAX_DAILY_QUERIES = 100  # Max queries per user per day
    
    @staticmethod
    def check_quota(db: Session, user_id: int) -> bool:
        """Check if user has remaining quota."""
        from datetime import date
        today = date.today()
        
        # Count today's queries for the user
        today_query_count = db.query(models.QueryHistory).filter(
            models.QueryHistory.user_id == user_id,
            models.QueryHistory.created_at >= today
        ).count()
        
        return today_query_count < LLMProxy.MAX_DAILY_QUERIES
    
    @staticmethod
    async def generate_response(query: str) -> str:
        """Generate response using Gemini API."""
        try:
            response = model.generate_content(query)
            return response.text
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"LLM service error: {str(e)}"
            )

@router.post("/submit_query", response_model=schemas.QueryResponse)
async def submit_query(
    query_request: schemas.QueryRequest,
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Submit query to LLM and save response."""
    
    # Check quota
    if not LLMProxy.check_quota(db, current_user.id):
        crud.create_audit_log(
            db=db,
            action="QUOTA_EXCEEDED",
            details=f"User {current_user.email} exceeded daily quota",
            user_id=current_user.id,
            ip_address=get_client_ip(request),
            severity="WARNING"
        )
        raise HTTPException(
            status_code=429,
            detail="Daily query quota exceeded"
        )
    
    # Check for sensitive data
    if crud.SensitiveDataScanner.contains_sensitive_data(query_request.query):
        crud.create_audit_log(
            db=db,
            action="SENSITIVE_DATA_DETECTED",
            details=f"Sensitive data detected in query from user {current_user.email}",
            user_id=current_user.id,
            ip_address=get_client_ip(request),
            severity="WARNING"
        )
        raise HTTPException(
            status_code=400,
            detail="Query contains sensitive data and cannot be processed"
        )
    
    try:
        # Generate response
        response_text = await LLMProxy.generate_response(query_request.query)
        
        # Save query and response
        query_history = crud.create_query(
            db=db,
            user_id=current_user.id,
            query=query_request.query,
            response=response_text
        )
        
        # Log successful query
        crud.create_audit_log(
            db=db,
            action="QUERY_PROCESSED",
            details=f"Query processed for user {current_user.email}",
            user_id=current_user.id,
            ip_address=get_client_ip(request),
            severity="INFO"
        )
        
        return query_history
        
    except Exception as e:
        # Log error
        crud.create_audit_log(
            db=db,
            action="QUERY_ERROR",
            details=f"Error processing query for user {current_user.email}: {str(e)}",
            user_id=current_user.id,
            ip_address=get_client_ip(request),
            severity="ERROR"
        )
        raise HTTPException(
            status_code=500,
            detail="Error processing query"
        )

@router.get("/history", response_model=schemas.HistoryResponse)
async def get_query_history(
    skip: int = 0,
    limit: int = 20,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's query history."""
    queries = crud.get_user_queries(db, current_user.id, skip, limit)
    total = crud.get_query_count(db, current_user.id)
    
    return {
        "queries": queries,
        "total": total
    }

@router.get("/quota")
async def get_quota_status(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's quota status."""
    from datetime import date
    today = date.today()
    
    used_queries = db.query(models.QueryHistory).filter(
        models.QueryHistory.user_id == current_user.id,
        models.QueryHistory.created_at >= today
    ).count()
    
    return {
        "daily_limit": LLMProxy.MAX_DAILY_QUERIES,
        "used_today": used_queries,
        "remaining": LLMProxy.MAX_DAILY_QUERIES - used_queries
    }