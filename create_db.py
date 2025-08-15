#!/usr/bin/env python3
"""
Database migration script to add conversation_history table and update query_history table
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
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()
        
        print("🔄 Running conversation history migration...")
        
        # Create conversation_history table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS conversation_history (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                conversation_title VARCHAR NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                is_active BOOLEAN DEFAULT true
            );
        """)
        print("✅ Created conversation_history table")
        
        # Check if conversation_master_id column exists in query_history
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'query_history' AND column_name = 'conversation_master_id';
        """)
        existing_column = cursor.fetchone()
        
        if not existing_column:
            cursor.execute("""
                ALTER TABLE query_history 
                ADD COLUMN conversation_master_id INTEGER REFERENCES conversation_history(id);
            """)
            print("✅ Added conversation_master_id column to query_history")
        else:
            print("ℹ️  conversation_master_id column already exists")
        
        # Create indexes for better performance
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_conversation_history_user_id ON conversation_history(user_id);
            CREATE INDEX IF NOT EXISTS idx_conversation_history_updated_at ON conversation_history(updated_at);
            CREATE INDEX IF NOT EXISTS idx_query_history_conversation_master_id ON query_history(conversation_master_id);
        """)
        print("✅ Created indexes")
        
        # Migrate existing queries to conversation_history
        cursor.execute("""
            SELECT DISTINCT user_id FROM query_history WHERE conversation_master_id IS NULL;
        """)
        users_with_orphaned_queries = cursor.fetchall()
        
        for (user_id,) in users_with_orphaned_queries:
            # Create a default conversation for existing queries
            cursor.execute("""
                INSERT INTO conversation_history (user_id, conversation_title, created_at, updated_at)
                VALUES (%s, 'Previous Conversation', NOW(), NOW())
                RETURNING id;
            """, (user_id,))
            conversation_id = cursor.fetchone()[0]
            
            # Update orphaned queries to belong to this conversation
            cursor.execute("""
                UPDATE query_history 
                SET conversation_master_id = %s 
                WHERE user_id = %s AND conversation_master_id IS NULL;
            """, (conversation_id, user_id))
        
        if users_with_orphaned_queries:
            print(f"✅ Migrated existing queries for {len(users_with_orphaned_queries)} users")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print("🎉 Migration completed successfully!")
        
    except Exception as e:
        print(f"❌ Error running migration: {e}")
        return False
    
    return True

def main():
    print("📊 SARA API Conversation History Migration")
    print("=" * 50)
    
    print("⚠️  Make sure to backup your database before running this migration!")
    confirm = input("Do you want to proceed? (y/N): ").lower().strip()
    
    if confirm not in ['y', 'yes']:
        print("Migration cancelled.")
        return
    
    if run_migration():
        print("\n✅ You can now restart your API server with conversation history support.")
    else:
        print("\n❌ Migration failed. Please check the error messages above.")

if __name__ == "__main__":
    main()