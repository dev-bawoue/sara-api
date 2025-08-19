from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from contextlib import asynccontextmanager
import logging
import traceback
import os

from app.bigquery_database import get_bq_db
from app.routers import auth, queries, admin, google_oauth

# Configure logging for Cloud Run
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        logger.info(" Starting SARA API...")
        
        # Initialize BigQuery database
        bq_db = get_bq_db()
        if bq_db.test_connection():
            logger.info(" BigQuery database connection successful")
        else:
            logger.error(" BigQuery database connection failed")
            raise Exception("Database connection failed")
        
        yield
        
    except Exception as e:
        logger.error(f" Startup error: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise
    finally:
        # Shutdown
        logger.info(" Application shutting down")

# Create FastAPI app
app = FastAPI(
    title="SARA API",
    description="Secure AI Response Assistant API with BigQuery and Google OAuth support",
    version="2.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Security
security = HTTPBearer()

def get_allowed_origins():
    """Get allowed origins for CORS."""
    # Default origins for development
    origins = [
        "http://localhost:3000", 
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ]
    
    # Get from environment variables
    frontend_url = os.getenv("FRONTEND_URL")
    backend_url = os.getenv("BACKEND_URL")
    
    if frontend_url:
        origins.append(frontend_url)
    if backend_url:
        origins.append(backend_url)
    
    # Common Google Cloud Run patterns
    project_id = os.getenv("PROJECT_ID", "precise-equator-274319")
    cloud_run_patterns = [
        f"https://sara-api-*.run.app",
        f"https://sara-frontend-*.run.app",
        f"https://*-{project_id.replace('precise-equator-', '')}.us-east1.run.app",
        "https://accounts.google.com",
        "https://oauth2.googleapis.com"
    ]
    origins.extend(cloud_run_patterns)
    
    # Remove duplicates
    origins = list(set(origins))
    
    logger.info(f" CORS allowed origins: {origins}")
    return origins

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, use specific origins
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=[
        "Accept",
        "Accept-Language",
        "Content-Language",
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "Origin",
        "Access-Control-Request-Method",
        "Access-Control-Request-Headers",
    ],
    expose_headers=["*"],
    max_age=3600,
)

# Include routers
app.include_router(auth.router)
app.include_router(queries.router)
app.include_router(admin.router)
app.include_router(google_oauth.router)

@app.get("/")
async def root():
    """Root endpoint."""
    environment = os.getenv("ENVIRONMENT", "development")
    project_id = os.getenv("PROJECT_ID", "unknown")
    
    return {
        "message": " SARA API is running with BigQuery",
        "version": "2.1.0",
        "status": "healthy",
        "environment": environment,
        "project_id": project_id,
        "port": os.getenv("PORT", "8080"),
        "database": "BigQuery",
        "authentication_methods": ["email_password", "google_oauth"],
        "endpoints": {
            "auth": ["/api/register", "/api/login", "/api/me"],
            "queries": ["/api/submit_query", "/api/history", "/api/quota", "/api/conversations"],
            "admin": ["/api/admin/logs", "/api/admin/users", "/api/admin/stats"],
            "google_oauth": ["/api/auth/google/login", "/api/auth/google/callback", "/api/auth/google/health"]
        },
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for Cloud Run."""
    try:
        # Test BigQuery connection
        bq_db = get_bq_db()
        connection_ok = bq_db.test_connection()
        
        environment = os.getenv("ENVIRONMENT", "development")
        project_id = os.getenv("PROJECT_ID", "unknown")
        
        health_data = {
            "status": "healthy" if connection_ok else "unhealthy",
            "database": "BigQuery",
            "database_connection": "connected" if connection_ok else "failed",
            "environment": environment,
            "project_id": project_id,
            "port": os.getenv("PORT", "8080"),
            "timestamp": str(datetime.now()),
            "version": "2.1.0"
        }
        
        if not connection_ok:
            health_data["message"] = "Database connection failed"
            return JSONResponse(status_code=503, content=health_data)
        
        health_data["message"] = "All systems operational"
        return health_data
        
    except Exception as e:
        logger.error(f" Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "message": "Service unavailable",
                "error": str(e),
                "timestamp": str(datetime.now())
            }
        )

# Handle CORS preflight requests
@app.options("/{path:path}")
async def options_handler(request: Request, path: str):
    """Handle all OPTIONS requests for CORS preflight."""
    return JSONResponse(
        {"message": "OK"},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
            "Access-Control-Allow-Headers": "Accept, Accept-Language, Content-Language, Content-Type, Authorization, X-Requested-With, Origin",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Max-Age": "3600"
        }
    )

# Custom error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with proper logging."""
    logger.warning(f" HTTP exception: {exc.status_code} - {exc.detail} - Path: {request.url.path}")
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "path": str(request.url.path),
            "timestamp": str(datetime.now())
        },
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors."""
    logger.warning(f" Validation error: {exc.errors()} - Path: {request.url.path}")
    
    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation Error",
            "details": exc.errors(),
            "status_code": 422,
            "path": str(request.url.path),
            "timestamp": str(datetime.now())
        },
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        }
    )

@app.exception_handler(500)
async def internal_server_error_handler(request: Request, exc: Exception):
    """Handle internal server errors."""
    error_id = str(id(exc))
    logger.error(f" Internal server error [{error_id}]: {str(exc)} - Path: {request.url.path}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "error_id": error_id,
            "status_code": 500,
            "path": str(request.url.path),
            "timestamp": str(datetime.now())
        },
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        }
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle any unhandled exceptions."""
    error_id = str(id(exc))
    logger.error(f" Unhandled exception [{error_id}]: {str(exc)} - Path: {request.url.path}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "error_id": error_id,
            "status_code": 500,
            "path": str(request.url.path),
            "timestamp": str(datetime.now())
        },
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        }
    )

# Import datetime for timestamps
from datetime import datetime

# Cloud Run compatible main function
if __name__ == "__main__":
    import uvicorn
    
    # Use PORT environment variable from Cloud Run, default to 8080
    port = int(os.environ.get("PORT", 8080))
    
    logger.info(f" Starting SARA API on port {port}")
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        log_level="info",
        access_log=True
    )