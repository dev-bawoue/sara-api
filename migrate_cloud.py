#!/usr/bin/env python3
"""
Database migration script for Cloud SQL PostgreSQL
Updated for synchronous SQLAlchemy and Cloud deployment
"""

import os
import sys
import logging
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker

# Add the app directory to the path so we can import our modules
sys.path.append(os.path.join(os.path.dirname(__file__), '.'))

try:
    from app import models
    from app.database import Base, get_database_url, engine as app_engine
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure you're running this from the project root directory")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_database_url_fallback():
    """Get database URL from environment with fallbacks."""
    database_url = os.getenv("DATABASE_URL")
    
    if not database_url:
        logger.error("DATABASE_URL environment variable not set!")
        logger.error("Examples:")
        logger.error("  Local: postgresql://postgres:password@localhost:5432/SARADATABASE")
        logger.error("  Cloud SQL: postgresql://user:password@/database?host=/cloudsql/project:region:instance")
        sys.exit(1)
    
    # Convert asyncpg to regular postgresql if needed
    if "postgresql+asyncpg://" in database_url:
        database_url = database_url.replace("postgresql+asyncpg://", "postgresql://")
    
    return database_url

def create_migration_engine():
    """Create engine specifically for migrations."""
    try:
        database_url = get_database_url_fallback()
        logger.info("Creating migration engine...")
        
        # Engine configuration for migrations
        engine = create_engine(
            database_url,
            pool_pre_ping=True,
            pool_recycle=3600,
            echo=False,  # Set to True for debugging
            connect_args={
                "connect_timeout": 30,
                "options": "-c timezone=UTC"
            }
        )
        
        return engine
    except Exception as e:
        logger.error(f"Failed to create migration engine: {e}")
        raise

def test_connection(engine):
    """Test database connection."""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT version()"))
            version = result.fetchone()[0]
            logger.info(f"✅ Database connection successful")
            logger.info(f"PostgreSQL version: {version}")
        return True
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        return False

def check_existing_tables(engine):
    """Check what tables already exist."""
    try:
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        logger.info(f"Existing tables: {existing_tables}")
        return existing_tables
    except Exception as e:
        logger.warning(f"Could not check existing tables: {e}")
        return []

def run_migrations(engine):
    """Run database migrations."""
    try:
        logger.info("🔄 Starting database migrations...")
        
        # Check existing tables
        existing_tables = check_existing_tables(engine)
        
        # Create all tables
        logger.info("📊 Creating/updating database tables...")
        Base.metadata.create_all(bind=engine)
        
        # Check what tables were created
        new_tables = check_existing_tables(engine)
        created_tables = set(new_tables) - set(existing_tables)
        
        if created_tables:
            logger.info(f"✅ Created tables: {list(created_tables)}")
        else:
            logger.info("✅ All tables already exist")
        
        logger.info("✅ Database tables created/updated successfully")
        
        # Run custom migrations
        logger.info("🔧 Running custom migrations...")
        run_custom_migrations(engine)
        
        logger.info("✅ All migrations completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

def run_custom_migrations(engine):
    """Run any custom SQL migrations."""
    try:
        with engine.begin() as conn:  # Use begin() for auto-commit
            logger.info("🔍 Creating database indexes...")
            
            migrations = [
                # User indexes
                """CREATE INDEX IF NOT EXISTS idx_users_email 
                   ON users(email);""",
                
                """CREATE INDEX IF NOT EXISTS idx_users_created_at 
                   ON users(created_at DESC);""",
                
                # Conversation history indexes
                """CREATE INDEX IF NOT EXISTS idx_conversation_history_user_id 
                   ON conversation_history(user_id);""",
                   
                """CREATE INDEX IF NOT EXISTS idx_conversation_history_updated_at 
                   ON conversation_history(updated_at DESC);""",
                
                """CREATE INDEX IF NOT EXISTS idx_conversation_history_user_updated 
                   ON conversation_history(user_id, updated_at DESC);""",
                   
                # Query history indexes
                """CREATE INDEX IF NOT EXISTS idx_query_history_conversation_master_id 
                   ON query_history(conversation_master_id);""",
                   
                """CREATE INDEX IF NOT EXISTS idx_query_history_user_id_created_at 
                   ON query_history(user_id, created_at DESC);""",
                
                """CREATE INDEX IF NOT EXISTS idx_query_history_created_at 
                   ON query_history(created_at DESC);""",
                   
                # Audit logs indexes
                """CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at 
                   ON audit_logs(created_at DESC);""",
                
                """CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id 
                   ON audit_logs(user_id);""",
                
                """CREATE INDEX IF NOT EXISTS idx_audit_logs_action 
                   ON audit_logs(action);""",
            ]
            
            for i, migration in enumerate(migrations, 1):
                try:
                    conn.execute(text(migration))
                    logger.debug(f"✅ Migration {i}/{len(migrations)} completed")
                except Exception as e:
                    logger.warning(f"⚠️ Migration {i} warning: {e}")
            
            logger.info("✅ Database indexes created successfully")
            
    except Exception as e:
        logger.error(f"❌ Custom migrations failed: {e}")
        raise

def create_admin_user(engine):
    """Create default admin user if needed."""
    try:
        from app import crud, schemas
        
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        
        admin_email = os.getenv("ADMIN_EMAIL", "admin@sara.com")
        admin_password = os.getenv("ADMIN_PASSWORD")
        
        if not admin_password:
            logger.info("ℹ️ No ADMIN_PASSWORD set, skipping admin user creation")
            db.close()
            return
        
        try:
            # Check if admin user exists
            existing_admin = crud.get_user_by_email(db, admin_email)
            if existing_admin:
                logger.info(f"ℹ️ Admin user already exists: {admin_email}")
                db.close()
                return
            
            # Create admin user
            admin_user = schemas.UserCreate(
                email=admin_email,
                password=admin_password,
                full_name="SARA Administrator",
                auth_provider="email"
            )
            
            created_user = crud.create_user(db, admin_user)
            logger.info(f"✅ Admin user created successfully: {admin_email}")
            
        except Exception as e:
            logger.error(f"❌ Error during admin user creation: {e}")
            db.rollback()
            raise
        finally:
            db.close()
            
    except ImportError:
        logger.warning("⚠️ Could not import crud/schemas modules for admin user creation")
    except Exception as e:
        logger.error(f"❌ Failed to create admin user: {e}")

def verify_deployment(engine):
    """Verify the deployment was successful."""
    try:
        logger.info("🔍 Verifying deployment...")
        
        # Check database connection
        if not test_connection(engine):
            return False
        
        # Check tables exist
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        expected_tables = ['users', 'conversation_history', 'query_history', 'audit_logs']
        missing_tables = [table for table in expected_tables if table not in tables]
        
        if missing_tables:
            logger.warning(f"⚠️ Missing expected tables: {missing_tables}")
        else:
            logger.info("✅ All expected tables present")
        
        # Check if we can create a session
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        result = db.execute(text("SELECT COUNT(*) FROM users"))
        user_count = result.fetchone()[0]
        db.close()
        
        logger.info(f"✅ Database verification complete. User count: {user_count}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Deployment verification failed: {e}")
        return False

def main():
    """Main migration function."""
    logger.info("🚀 Starting SARA API database migrations...")
    logger.info("=" * 50)
    
    try:
        # Create migration engine
        engine = create_migration_engine()
        
        # Test connection first
        if not test_connection(engine):
            logger.error("❌ Cannot connect to database. Aborting migration.")
            sys.exit(1)
        
        # Run migrations
        if not run_migrations(engine):
            logger.error("❌ Migrations failed")
            sys.exit(1)
        
        # Create admin user
        logger.info("👤 Setting up admin user...")
        create_admin_user(engine)
        
        # Verify deployment
        if verify_deployment(engine):
            logger.info("🎉 All migrations completed successfully!")
            logger.info("=" * 50)
            logger.info("Next steps:")
            logger.info("1. Test your API endpoints")
            logger.info("2. Check the admin user login")
            logger.info("3. Monitor the application logs")
        else:
            logger.warning("⚠️ Migrations completed but verification failed")
            
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"❌ Migration process failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)
    finally:
        # Clean up
        try:
            if 'engine' in locals():
                engine.dispose()
        except:
            pass

if __name__ == "__main__":
    main()