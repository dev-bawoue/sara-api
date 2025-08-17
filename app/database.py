#!/usr/bin/env python3
"""
Database configuration for SARA API with Cloud SQL PostgreSQL support
Supports both local development and Google Cloud deployment
"""

import os
import logging
from sqlalchemy import create_engine, MetaData, event, pool
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL")

# Convert asyncpg URL to regular postgresql URL if needed
if DATABASE_URL and "postgresql+asyncpg://" in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")

# Detect if running on Cloud Run or locally
def is_cloud_run():
    """Check if running on Google Cloud Run"""
    return os.getenv('K_SERVICE') is not None

def get_database_url():
    """Get the appropriate database URL based on environment"""
    if not DATABASE_URL:
        if is_cloud_run():
            logger.error("DATABASE_URL not set in Cloud Run environment")
            raise ValueError("DATABASE_URL environment variable required")
        else:
            # Fallback for local development
            logger.warning("DATABASE_URL not set, using default local PostgreSQL")
            return "postgresql://postgres:postgres@localhost:5432/SARADATABASE"
    
    return DATABASE_URL

# Database URL
db_url = get_database_url()
logger.info(f"Database URL configured: {db_url[:50]}...")

# Engine configuration
engine_kwargs = {
    "pool_pre_ping": True,
    "pool_recycle": 3600,  # Recycle connections after 1 hour
    "pool_timeout": 30,
    "echo": False,  # Set to True for SQL debugging
}

# Cloud SQL specific configuration
if "/cloudsql/" in db_url:
    logger.info("Detected Cloud SQL connection")
    engine_kwargs.update({
        "poolclass": NullPool,  # Use NullPool for Cloud SQL
        "connect_args": {
            "connect_timeout": 30,
            "options": "-c timezone=UTC"
        }
    })
else:
    logger.info("Using standard PostgreSQL connection")
    engine_kwargs.update({
        "pool_size": 10,
        "max_overflow": 20,
        "connect_args": {
            "connect_timeout": 10,
            "options": "-c timezone=UTC"
        }
    })

# Create SQLAlchemy engine
try:
    engine = create_engine(db_url, **engine_kwargs)
    logger.info("Database engine created successfully")
except Exception as e:
    logger.error(f"Failed to create database engine: {e}")
    raise

# Create sessionmaker
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False
)

# Create declarative base
Base = declarative_base()

# Metadata for table operations
metadata = MetaData()

# Legacy compatibility - remove async database operations
database = None

# Connection event listeners for better Cloud SQL compatibility
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Set database connection parameters"""
    if 'postgresql' in str(dbapi_connection):
        with dbapi_connection.cursor() as cursor:
            # Set timezone to UTC
            cursor.execute("SET timezone TO 'UTC'")
            # Set connection encoding
            cursor.execute("SET client_encoding TO 'utf8'")

@event.listens_for(engine, "checkout")
def receive_checkout(dbapi_connection, connection_record, connection_proxy):
    """Handle connection checkout for Cloud SQL"""
    logger.debug("Database connection checked out")

def get_db():
    """
    Dependency to get database session
    Use this in FastAPI route dependencies
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()

def get_db_sync():
    """
    Get synchronous database session
    Use for scripts and migrations
    """
    return SessionLocal()

def test_connection():
    """Test database connection"""
    try:
        db = SessionLocal()
        db.execute("SELECT 1")
        db.close()
        logger.info("Database connection test successful")
        return True
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        return False

def close_db_connections():
    """Close all database connections"""
    try:
        engine.dispose()
        logger.info("Database connections closed")
    except Exception as e:
        logger.error(f"Error closing database connections: {e}")

# Health check function
def get_db_health():
    """Get database health status"""
    try:
        db = SessionLocal()
        result = db.execute("SELECT version()")
        version = result.fetchone()[0]
        db.close()
        return {
            "status": "healthy",
            "database": "postgresql",
            "version": version,
            "connection_url": db_url[:50] + "..." if len(db_url) > 50 else db_url
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "database": "postgresql"
        }

# Export main components
__all__ = [
    'engine',
    'SessionLocal', 
    'Base',
    'metadata',
    'get_db',
    'get_db_sync',
    'test_connection',
    'get_db_health',
    'close_db_connections'
]

# Initialize database on import for local development
if __name__ == "__main__":
    print("Testing database connection...")
    if test_connection():
        print("✅ Database connection successful")
        health = get_db_health()
        print(f"Database version: {health.get('version', 'Unknown')}")
    else:
        print("❌ Database connection failed")