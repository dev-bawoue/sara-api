from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from contextlib import asynccontextmanager
import logging
import traceback
import os

from app.database import engine
from app import models
from app.routers import auth, queries, admin, google_oauth

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        # Create database tables
        models.Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        
        yield
        
    except Exception as e:
        logger.error(f"Startup error: {e}")
        raise
    finally:
        # Shutdown
        logger.info("Application shutting down")

# Create FastAPI app
app = FastAPI(
    title="SARA API",
    description="Secure AI Response Assistant API with Email/Password and Google OAuth support",
    version="1.0.0",
    lifespan=lifespan
)

# Security
security = HTTPBearer()

# CORS middleware - Updated for Cloud Run
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", 
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
        "https://*.run.app",  # Allow Cloud Run domains
        "https://*.googleapis.com",  # Allow Google services
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(queries.router)
app.include_router(admin.router)
app.include_router(google_oauth.router)  # Enable Google OAuth

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "SARA API is running",
        "version": "1.0.0",
        "status": "healthy",
        "environment": os.getenv("ENVIRONMENT", "development"),
        "port": os.getenv("PORT", "8000"),
        "authentication_methods": ["email_password", "google_oauth"],
        "endpoints": {
            "auth": ["/api/register", "/api/login", "/api/me"],
            "queries": ["/api/submit_query", "/api/history", "/api/quota"],
            "admin": ["/api/admin/logs", "/api/admin/users", "/api/admin/stats"],
            "google_oauth": ["/auth/google/login", "/auth/google/callback", "/auth/google/token"]
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for Cloud Run."""
    try:
        # Test database connection
        from app.database import engine
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        return {
            "status": "healthy",
            "database": "connected",
            "message": "All systems operational",
            "environment": os.getenv("ENVIRONMENT", "development"),
            "port": os.getenv("PORT", "8000")
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=503,
            detail="Service unavailable"
        )

# Custom error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with proper logging."""
    logger.warning(f"HTTP exception: {exc.status_code} - {exc.detail} - Path: {request.url.path}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "path": str(request.url.path)
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors."""
    logger.warning(f"Validation error: {exc.errors()} - Path: {request.url.path}")
    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation Error",
            "details": exc.errors(),
            "status_code": 422,
            "path": str(request.url.path)
        }
    )

@app.exception_handler(500)
async def internal_server_error_handler(request: Request, exc: Exception):
    """Handle internal server errors."""
    error_id = id(exc)  # Simple error tracking
    logger.error(f"Internal server error [{error_id}]: {str(exc)} - Path: {request.url.path}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "error_id": error_id,
            "status_code": 500,
            "path": str(request.url.path)
        }
    )

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Handle 404 errors."""
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not Found",
            "message": "The requested resource was not found",
            "status_code": 404,
            "path": str(request.url.path)
        }
    )

# Global exception handler for any unhandled exceptions
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle any unhandled exceptions."""
    error_id = id(exc)
    logger.error(f"Unhandled exception [{error_id}]: {str(exc)} - Path: {request.url.path}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "error_id": error_id,
            "status_code": 500,
            "path": str(request.url.path)
        }
    )

# Cloud Run compatible main function
if __name__ == "__main__":
    import uvicorn
    # Use PORT environment variable from Cloud Run, default to 8080
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        log_level="info"
    )