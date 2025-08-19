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

from app.bigquery_database import get_bq_db
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
        # Initialize BigQuery database
        bq_db = get_bq_db()
        if bq_db.test_connection():
            logger.info("BigQuery database connection successful")
        else:
            logger.error("BigQuery database connection failed")
            raise Exception("Database connection failed")
        
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
    description="Secure AI Response Assistant API with BigQuery and Google OAuth support",
    version="2.0.0",
    lifespan=lifespan
)

# Security
security = HTTPBearer()

# Get the current Cloud Run service URL
def get_cloud_run_origins():
    """Get allowed origins for Cloud Run deployment."""
    origins = [
        "http://localhost:3000", 
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
    ]
    
    # Add the specific Cloud Run URLs
    cloud_run_urls = [
        "https://sara-api-update-1024279616298.us-east1.run.app",
        "https://sara-frontend-1024279616298.us-east1.run.app"
    ]
    origins.extend(cloud_run_urls)
    
    # Add other Google service origins that might be needed
    google_origins = [
        "https://accounts.google.com",
        "https://oauth2.googleapis.com",
        "https://www.googleapis.com",
    ]
    origins.extend(google_origins)
    
    # If we have a frontend URL environment variable, add it
    frontend_url = os.getenv("FRONTEND_URL")
    if frontend_url and frontend_url not in origins:
        origins.append(frontend_url)
    
    logger.info(f"CORS allowed origins: {origins}")
    return origins

# CORS middleware - Fixed for Cloud Run
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cloud_run_origins(),
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
    max_age=3600,  # Cache preflight for 1 hour
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
        "message": "SARA API is running with BigQuery",
        "version": "2.0.0",
        "status": "healthy",
        "environment": os.getenv("ENVIRONMENT", "development"),
        "port": os.getenv("PORT", "8000"),
        "database": "BigQuery",
        "authentication_methods": ["email_password", "google_oauth"],
        "cors_origins": get_cloud_run_origins(),
        "endpoints": {
            "auth": ["/api/register", "/api/login", "/api/me"],
            "queries": ["/api/submit_query", "/api/history", "/api/quota"],
            "admin": ["/api/admin/logs", "/api/admin/users", "/api/admin/stats"],
            "google_oauth": ["/api/auth/google/login", "/api/auth/google/callback", "/api/auth/google/health"]
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for Cloud Run."""
    try:
        # Test BigQuery connection
        bq_db = get_bq_db()
        connection_ok = bq_db.test_connection()
        
        return {
            "status": "healthy" if connection_ok else "unhealthy",
            "database": "BigQuery",
            "database_connection": "connected" if connection_ok else "failed",
            "message": "All systems operational" if connection_ok else "Database connection failed",
            "environment": os.getenv("ENVIRONMENT", "development"),
            "port": os.getenv("PORT", "8000"),
            "cors_configured": True,
            "allowed_origins": get_cloud_run_origins()
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=503,
            detail="Service unavailable"
        )

# Add a specific CORS test endpoint
@app.options("/{path:path}")
async def options_handler(request: Request, path: str):
    """Handle all OPTIONS requests for CORS preflight."""
    response = JSONResponse({"message": "OK"})
    origin = request.headers.get("origin")
    
    if origin in get_cloud_run_origins():
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
        response.headers["Access-Control-Allow-Headers"] = "Accept, Accept-Language, Content-Language, Content-Type, Authorization, X-Requested-With, Origin"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Max-Age"] = "3600"
    
    return response

# Custom error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with proper logging."""
    logger.warning(f"HTTP exception: {exc.status_code} - {exc.detail} - Path: {request.url.path}")
    
    response = JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "path": str(request.url.path)
        }
    )
    
    # Add CORS headers to error responses
    origin = request.headers.get("origin")
    if origin in get_cloud_run_origins():
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    
    return response

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors."""
    logger.warning(f"Validation error: {exc.errors()} - Path: {request.url.path}")
    
    response = JSONResponse(
        status_code=422,
        content={
            "error": "Validation Error",
            "details": exc.errors(),
            "status_code": 422,
            "path": str(request.url.path)
        }
    )
    
    # Add CORS headers to error responses
    origin = request.headers.get("origin")
    if origin in get_cloud_run_origins():
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    
    return response

@app.exception_handler(500)
async def internal_server_error_handler(request: Request, exc: Exception):
    """Handle internal server errors."""
    error_id = id(exc)  # Simple error tracking
    logger.error(f"Internal server error [{error_id}]: {str(exc)} - Path: {request.url.path}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    
    response = JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "error_id": error_id,
            "status_code": 500,
            "path": str(request.url.path)
        }
    )
    
    # Add CORS headers to error responses
    origin = request.headers.get("origin")
    if origin in get_cloud_run_origins():
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    
    return response

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Handle 404 errors."""
    response = JSONResponse(
        status_code=404,
        content={
            "error": "Not Found",
            "message": "The requested resource was not found",
            "status_code": 404,
            "path": str(request.url.path)
        }
    )
    
    # Add CORS headers to error responses
    origin = request.headers.get("origin")
    if origin in get_cloud_run_origins():
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    
    return response

# Global exception handler for any unhandled exceptions
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle any unhandled exceptions."""
    error_id = id(exc)
    logger.error(f"Unhandled exception [{error_id}]: {str(exc)} - Path: {request.url.path}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    
    response = JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "error_id": error_id,
            "status_code": 500,
            "path": str(request.url.path)
        }
    )
    
    # Add CORS headers to error responses
    origin = request.headers.get("origin")
    if origin in get_cloud_run_origins():
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    
    return response

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