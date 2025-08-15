from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List
import google.generativeai as genai
import os
from app.database import get_db
from app import schemas, models, crud
from app.dependencies import get_current_user, get_client_ip

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash")

router = APIRouter(prefix="/api", tags=["queries"])

class LLMProxy:
    MAX_DAILY_QUERIES = 100
    
    @staticmethod
    def check_quota(db: Session, user_id: int) -> bool:
        from datetime import date
        today = date.today()
        
        today_query_count = db.query(models.QueryHistory).filter(
            models.QueryHistory.user_id == user_id,
            models.QueryHistory.created_at >= today
        ).count()
        
        return today_query_count < LLMProxy.MAX_DAILY_QUERIES
    
    @staticmethod
    async def generate_response(query: str) -> str:
        try:
            response = model.generate_content(query)
            return response.text
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"LLM service error: {str(e)}"
            )

@router.post("/conversations", response_model=schemas.ConversationResponse)
async def create_conversation(
    conversation_request: schemas.ConversationRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    conversation = crud.create_conversation(
        db=db,
        user_id=current_user.id,
        title=conversation_request.title
    )
    
    return {
        "id": conversation.id,
        "conversation_title": conversation.conversation_title,
        "created_at": conversation.created_at,
        "updated_at": conversation.updated_at,
        "is_active": conversation.is_active,
        "query_count": 0
    }

@router.get("/conversations", response_model=schemas.ConversationHistoryResponse)
async def get_conversations(
    skip: int = 0,
    limit: int = 20,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    conversations = crud.get_user_conversations(db, current_user.id, skip, limit)
    total = crud.get_conversation_count(db, current_user.id)
    
    return {
        "conversations": conversations,
        "total": total
    }

@router.get("/conversations/{conversation_id}/queries", response_model=List[schemas.QueryResponse])
async def get_conversation_queries(
    conversation_id: int,
    skip: int = 0,
    limit: int = 100,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    conversation = db.query(models.ConversationHistory).filter(
        models.ConversationHistory.id == conversation_id,
        models.ConversationHistory.user_id == current_user.id
    ).first()
    
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    queries = crud.get_conversation_queries(db, conversation_id, skip, limit)
    return queries

@router.post("/submit_query", response_model=schemas.QueryResponse)
async def submit_query(
    query_request: schemas.QueryRequest,
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
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
    
    conversation_id = query_request.conversation_master_id
    if not conversation_id:
        first_words = query_request.query.split()[:6]
        title = " ".join(first_words) + ("..." if len(query_request.query.split()) > 6 else "")
        conversation = crud.create_conversation(
            db=db,
            user_id=current_user.id,
            title=title
        )
        conversation_id = conversation.id
    
    try:
        response_text = await LLMProxy.generate_response(query_request.query)
        
        query_history = crud.create_query(
            db=db,
            user_id=current_user.id,
            query=query_request.query,
            response=response_text,
            conversation_master_id=conversation_id
        )
        
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

@router.put("/conversations/{conversation_id}")
async def update_conversation(
    conversation_id: int,
    conversation_request: schemas.ConversationRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    conversation = db.query(models.ConversationHistory).filter(
        models.ConversationHistory.id == conversation_id,
        models.ConversationHistory.user_id == current_user.id
    ).first()
    
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    crud.update_conversation_title(db, conversation_id, conversation_request.title)
    return {"message": "Conversation updated successfully"}

@router.delete("/conversations/{conversation_id}")
async def delete_conversation(
    conversation_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    conversation = db.query(models.ConversationHistory).filter(
        models.ConversationHistory.id == conversation_id,
        models.ConversationHistory.user_id == current_user.id
    ).first()
    
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    crud.delete_conversation(db, conversation_id, current_user.id)
    return {"message": "Conversation deleted successfully"}

@router.get("/history", response_model=schemas.HistoryResponse)
async def get_query_history(
    skip: int = 0,
    limit: int = 20,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
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