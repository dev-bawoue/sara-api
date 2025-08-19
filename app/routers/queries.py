from fastapi import APIRouter, Depends, HTTPException, Request
from typing import List
import google.generativeai as genai
import os
from app.bigquery_database import get_bq_db
from app import schemas
from app import bigquery_crud as crud
from app.bigquery_models import User, ConversationHistory
from app.dependencies import get_current_user, get_client_ip

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash")

router = APIRouter(prefix="/api", tags=["queries"])

class LLMProxy:
    MAX_DAILY_QUERIES = 100
    
    @staticmethod
    def check_quota(user_id: str) -> bool:
        from datetime import date
        today = date.today()
        
        today_query_count = crud.get_daily_query_count(user_id, today)
        
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
    current_user: User = Depends(get_current_user)
):
    conversation = crud.create_conversation(
        user_id=current_user.id,
        title=conversation_request.title
    )
    
    return {
        "id": conversation.encrypted_id,  # Return encrypted ID
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
    current_user: User = Depends(get_current_user)
):
    conversations = crud.get_user_conversations(current_user.id, skip, limit)
    total = crud.get_conversation_count(current_user.id)
    
    return {
        "conversations": conversations,
        "total": total
    }

@router.get("/conversations/{conversation_id}/queries", response_model=List[schemas.QueryResponse])
async def get_conversation_queries(
    conversation_id: str,  # This will be the encrypted ID
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user)
):
    conversation = crud.get_conversation_by_id(conversation_id, current_user.id)
    
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    queries = crud.get_conversation_queries(conversation_id, skip, limit)
    
    # Convert to response format with encrypted IDs
    query_responses = []
    for query in queries:
        query_responses.append(schemas.QueryResponse(
            id=query.encrypted_id,  # Use encrypted ID
            query=query.query,
            response=query.response,
            conversation_master_id=conversation.encrypted_id,  # Use encrypted conversation ID
            created_at=query.created_at,
            is_sensitive=query.is_sensitive
        ))
    
    return query_responses

@router.post("/submit_query", response_model=schemas.QueryResponse)
async def submit_query(
    query_request: schemas.QueryRequest,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    if not LLMProxy.check_quota(current_user.id):
        crud.create_audit_log(
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
        # Create new conversation
        first_words = query_request.query.split()[:6]
        title = " ".join(first_words) + ("..." if len(query_request.query.split()) > 6 else "")
        conversation = crud.create_conversation(
            user_id=current_user.id,
            title=title
        )
        conversation_id = conversation.id  # Use internal ID for database operations
        encrypted_conversation_id = conversation.encrypted_id  # For response
    else:
        # Use existing conversation - conversation_id here is encrypted
        conversation = crud.get_conversation_by_id(conversation_id, current_user.id)
        if not conversation:
            raise HTTPException(status_code=404, detail="Conversation not found")
        encrypted_conversation_id = conversation.encrypted_id
        conversation_id = conversation.id  # Use internal ID for database operations
    
    try:
        response_text = await LLMProxy.generate_response(query_request.query)
        
        query_history = crud.create_query(
            user_id=current_user.id,
            query=query_request.query,
            response=response_text,
            conversation_master_id=conversation_id  # Use internal ID
        )
        
        crud.create_audit_log(
            action="QUERY_PROCESSED",
            details=f"Query processed for user {current_user.email}",
            user_id=current_user.id,
            ip_address=get_client_ip(request),
            severity="INFO"
        )
        
        # Convert to response format with encrypted IDs
        return schemas.QueryResponse(
            id=query_history.encrypted_id,
            query=query_history.query,
            response=query_history.response,
            conversation_master_id=encrypted_conversation_id,  # Return encrypted conversation ID
            created_at=query_history.created_at,
            is_sensitive=query_history.is_sensitive
        )
        
    except Exception as e:
        crud.create_audit_log(
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
    conversation_id: str,  # Encrypted ID
    conversation_request: schemas.ConversationRequest,
    current_user: User = Depends(get_current_user)
):
    conversation = crud.get_conversation_by_id(conversation_id, current_user.id)
    
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    crud.update_conversation_title(conversation_id, conversation_request.title)
    return {"message": "Conversation updated successfully"}

@router.delete("/conversations/{conversation_id}")
async def delete_conversation(
    conversation_id: str,  # Encrypted ID
    current_user: User = Depends(get_current_user)
):
    conversation = crud.get_conversation_by_id(conversation_id, current_user.id)
    
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    crud.delete_conversation(conversation_id, current_user.id)
    return {"message": "Conversation deleted successfully"}

@router.get("/history", response_model=schemas.HistoryResponse)
async def get_query_history(
    skip: int = 0,
    limit: int = 20,
    current_user: User = Depends(get_current_user)
):
    queries = crud.get_user_queries(current_user.id, skip, limit)
    total = crud.get_query_count(current_user.id)
    
    # Convert to response format with encrypted IDs
    query_responses = []
    for query in queries:
        # Get conversation for this query to get encrypted ID
        conversation = None
        if query.conversation_master_id:
            try:
                conversation = crud.get_conversation_by_id(query.conversation_master_id, current_user.id)
            except:
                pass
        
        query_responses.append(schemas.QueryResponse(
            id=query.encrypted_id,
            query=query.query,
            response=query.response,
            conversation_master_id=conversation.encrypted_id if conversation else "unknown",
            created_at=query.created_at,
            is_sensitive=query.is_sensitive
        ))
    
    return {
        "queries": query_responses,
        "total": total
    }

@router.get("/quota")
async def get_quota_status(
    current_user: User = Depends(get_current_user)
):
    from datetime import date
    today = date.today()
    
    used_queries = crud.get_daily_query_count(current_user.id, today)
    
    return {
        "daily_limit": LLMProxy.MAX_DAILY_QUERIES,
        "used_today": used_queries,
        "remaining": LLMProxy.MAX_DAILY_QUERIES - used_queries
    }