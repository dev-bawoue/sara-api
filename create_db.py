#!/usr/bin/env python3
"""
Database initialization script for SARA API
Run this script to create the PostgreSQL database and tables.
"""

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import os
from dotenv import load_dotenv

load_dotenv()

# Database connection parameters
DB_HOST = "localhost"
DB_PORT = "5432"
DB_USER = "postgres"  # Replace with your PostgreSQL username
DB_PASSWORD = ""  # Replace with your PostgreSQL password
DB_NAME = "SARALOGIN"

def create_database():
    """Create the SARALOGIN database if it doesn't exist."""
    try:
        # Connect to PostgreSQL server (not to a specific database)
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database="postgres"  # Connect to default postgres database
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute(
            "SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s",
            (DB_NAME.lower(),)
        )
        exists = cursor.fetchone()
        
        if not exists:
            cursor.execute(f'CREATE DATABASE "{DB_NAME}"')
            print(f" Database '{DB_NAME}' created successfully!")
        else:
            print(f"ℹ  Database '{DB_NAME}' already exists.")
            
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f" Error creating database: {e}")
        return False
    
    return True

def create_tables():
    """Create tables using SQLAlchemy."""
    try:
        from app.database import engine
        from app import models
        
        # Create all tables
        models.Base.metadata.create_all(bind=engine)
        print(" All tables created successfully!")
        
    except Exception as e:
        print(f" Error creating tables: {e}")
        return False
    
    return True

def create_admin_user():
    """Create an admin user."""
    try:
        from sqlalchemy.orm import sessionmaker
        from app.database import engine
        from app import models, auth
        
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Check if admin user exists
        admin_email = "admin@sara.com"
        existing_admin = session.query(models.User).filter(
            models.User.email == admin_email
        ).first()
        
        if not existing_admin:
            # Create admin user
            hashed_password = auth.get_password_hash("admin123")  # Change this password!
            admin_user = models.User(
                email=admin_email,
                hashed_password=hashed_password,
                is_active=True
            )
            session.add(admin_user)
            session.commit()
            print(f" Admin user created: {admin_email} (password: admin123)")
            print("  IMPORTANT: Change the admin password after first login!")
        else:
            print(f"ℹ  Admin user already exists: {admin_email}")
        
        session.close()
        
    except Exception as e:
        print(f" Error creating admin user: {e}")
        return False
    
    return True

def main():
    """Main initialization function."""
    print(" Initializing SARA API Database...")
    print("=" * 50)
    
    # Step 1: Create database
    print("1. Creating database...")
    if not create_database():
        print(" Database creation failed. Exiting.")
        return
    
    # Step 2: Create tables
    print("\n2. Creating tables...")
    if not create_tables():
        print(" Table creation failed. Exiting.")
        return
    
    # Step 3: Create admin user
    print("\n3. Creating admin user...")
    if not create_admin_user():
        print(" Admin user creation failed. Exiting.")
        return
    
    print("\n" + "=" * 50)
    print(" Database initialization completed successfully!")
    print("\n Next steps:")
    print("1. Update your .env file with the correct DATABASE_URL")
    print("2. Install requirements: pip install -r requirements.txt")
    print("3. Run the API: python -m uvicorn app.main:app --reload")
    print("4. Access the API documentation at: http://localhost:8000/docs")

if __name__ == "__main__":
    main()