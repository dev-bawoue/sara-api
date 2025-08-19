#!/usr/bin/env python3
"""
BigQuery initialization script
Creates tables, roles, and initial admin user
"""

import os
import sys
import logging
from app.bigquery_database import get_bq_db
from app import bigquery_crud as crud, schemas, auth

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def initialize_bigquery():
    """Initialize BigQuery database with tables and default data."""
    try:
        logger.info(" Starting BigQuery initialization...")
        
        # Get database instance (this will create tables if they don't exist)
        bq_db = get_bq_db()
        
        # Test connection
        if not bq_db.test_connection():
            raise Exception("Cannot connect to BigQuery")
        
        logger.info(" BigQuery connection successful")
        
        # Check if roles exist
        admin_role = crud.get_role_by_name('admin')
        client_role = crud.get_role_by_name('client')
        
        if not admin_role or not client_role:
            logger.info(" Roles not found, they should be created automatically by database initialization")
            # The roles are created automatically in _initialize_default_roles method
            admin_role = crud.get_role_by_name('admin')
            client_role = crud.get_role_by_name('client')
        
        if admin_role and client_role:
            logger.info(" Roles initialized successfully")
            logger.info(f"   - Admin role ID: {admin_role.id}")
            logger.info(f"   - Client role ID: {client_role.id}")
        else:
            raise Exception("Failed to initialize roles")
        
        return True
        
    except Exception as e:
        logger.error(f" BigQuery initialization failed: {e}")
        return False

def create_initial_admin():
    """Create initial admin user if it doesn't exist."""
    try:
        admin_email = os.getenv("ADMIN_EMAIL", "admin@sara.com")
        admin_password = os.getenv("ADMIN_PASSWORD")
        
        if not admin_password:
            logger.warning("  No ADMIN_PASSWORD environment variable set")
            logger.warning("    Admin user will not be created")
            return False
        
        # Check if admin user already exists
        existing_admin = crud.get_user_by_email(admin_email)
        if existing_admin:
            logger.info(f"  Admin user already exists: {admin_email}")
            
            # Check if existing user is actually an admin
            if crud.is_user_admin(existing_admin):
                logger.info(" Existing user has admin role")
            else:
                logger.warning("  Existing user does not have admin role")
            
            return True
        
        # Create admin user
        logger.info(f" Creating initial admin user: {admin_email}")
        
        admin_user_data = schemas.UserCreate(
            email=admin_email,
            password=admin_password,
            full_name="SARA Administrator",
            auth_provider="email"
        )
        
        admin_user = crud.create_admin_user(admin_user_data)
        
        # Create audit log entry
        crud.create_audit_log(
            action="INITIAL_ADMIN_CREATED",
            details=f"Initial admin user created during system initialization: {admin_email}",
            user_id=admin_user.id,
            severity="INFO"
        )
        
        logger.info(" Initial admin user created successfully")
        return True
        
    except Exception as e:
        logger.error(f" Failed to create initial admin user: {e}")
        return False

def verify_setup():
    """Verify that the setup is correct."""
    try:
        logger.info(" Verifying setup...")
        
        # Check roles
        admin_role = crud.get_role_by_name('admin')
        client_role = crud.get_role_by_name('client')
        
        if not admin_role:
            logger.error(" Admin role not found")
            return False
        
        if not client_role:
            logger.error(" Client role not found")
            return False
        
        # Check admin user
        admin_email = os.getenv("ADMIN_EMAIL", "admin@sara.com")
        admin_user = crud.get_user_by_email(admin_email)
        
        if not admin_user:
            logger.warning(f"  Admin user not found: {admin_email}")
        elif not crud.is_user_admin(admin_user):
            logger.error(f" User {admin_email} exists but is not an admin")
            return False
        else:
            logger.info(f" Admin user verified: {admin_email}")
        
        # Get system stats
        try:
            stats = crud.get_system_stats()
            logger.info(" System statistics:")
            logger.info(f"   - Total users: {stats['total_users']}")
            logger.info(f"   - Total queries: {stats['total_queries']}")
        except Exception as e:
            logger.warning(f"  Could not retrieve system stats: {e}")
        
        logger.info(" Setup verification completed")
        return True
        
    except Exception as e:
        logger.error(f" Setup verification failed: {e}")
        return False

def main():
    """Main initialization function."""
    logger.info(" SARA API BigQuery Initialization")
    logger.info("=" * 40)
    
    success = True
    
    # Step 1: Initialize BigQuery
    if not initialize_bigquery():
        success = False
    
    # Step 2: Create initial admin user
    if success and not create_initial_admin():
        logger.warning("  Could not create initial admin user")
        # Don't mark as failure since the system can still work
    
    # Step 3: Verify setup
    if success and not verify_setup():
        success = False
    
    if success:
        logger.info("🎉 BigQuery initialization completed successfully!")
        logger.info("=" * 40)
        logger.info("Next steps:")
        logger.info("1. Test the API endpoints")
        logger.info("2. Login with the admin user")
        logger.info("3. Register regular users via the API")
        logger.info("4. Monitor the application")
    else:
        logger.error(" BigQuery initialization failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()