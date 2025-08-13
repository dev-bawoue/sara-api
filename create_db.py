#!/usr/bin/env python3
"""
Database migration script to add OAuth columns to existing User table
Run this script to update your existing database schema.
"""

import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

DB_HOST = "localhost"
DB_PORT = "5432"
DB_USER = "postgres"  
DB_PASSWORD = ""  
DB_NAME = "SARADATABASE"  

def run_migration():
    """Add OAuth columns to existing users table."""
    try:
        # Connect to your SARADATABASE database
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()
        
        print(" Running database migration...")
        
        # Check if columns already exist
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name IN ('auth_provider', 'full_name', 'avatar_url');
        """)
        existing_columns = [row[0] for row in cursor.fetchall()]
        
        # Add auth_provider column if it doesn't exist
        if 'auth_provider' not in existing_columns:
            cursor.execute("""
                ALTER TABLE users 
                ADD COLUMN auth_provider VARCHAR DEFAULT 'email';
            """)
            print(" Added auth_provider column")
        else:
            print("  auth_provider column already exists")
        
        # Add full_name column if it doesn't exist
        if 'full_name' not in existing_columns:
            cursor.execute("""
                ALTER TABLE users 
                ADD COLUMN full_name VARCHAR;
            """)
            print(" Added full_name column")
        else:
            print("  full_name column already exists")
        
        # Add avatar_url column if it doesn't exist
        if 'avatar_url' not in existing_columns:
            cursor.execute("""
                ALTER TABLE users 
                ADD COLUMN avatar_url VARCHAR;
            """)
            print(" Added avatar_url column")
        else:
            print("  avatar_url column already exists")
        
        # Update existing users to have 'email' as auth_provider
        cursor.execute("""
            UPDATE users 
            SET auth_provider = 'email' 
            WHERE auth_provider IS NULL;
        """)
        print(" Updated existing users with email auth provider")
        
        # Commit changes
        conn.commit()
        cursor.close()
        conn.close()
        
        print("\ Migration completed successfully!")
        
    except Exception as e:
        print(f" Error running migration: {e}")
        return False
    
    return True

def main():
    """Main migration function."""
    print(" SARA API Database Migration")
    print("=" * 40)
    
    print("  Make sure to backup your database before running this migration!")
    confirm = input("Do you want to proceed? (y/N): ").lower().strip()
    
    if confirm not in ['y', 'yes']:
        print("Migration cancelled.")
        return
    
    if run_migration():
        print("\n You can now restart your API server.")
    else:
        print("\n Migration failed. Please check the error messages above.")

if __name__ == "__main__":
    main()