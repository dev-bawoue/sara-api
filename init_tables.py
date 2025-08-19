#!/usr/bin/env python3
"""
Manual BigQuery table creation script
Run this if you want to create tables manually
"""

import os
from google.cloud import bigquery
from google.oauth2 import service_account

def create_tables():
    # Initialize BigQuery client
    client = bigquery.Client(project="precise-equator-274319")
    dataset_id = "sara_dataset"
    
    # Table schemas
    tables_schema = {
        "roles": [
            bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("name", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("created_at", "TIMESTAMP", mode="REQUIRED"),
        ],
        "users": [
            bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("encrypted_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("email", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("hashed_password", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("is_active", "BOOLEAN", mode="REQUIRED"),
            bigquery.SchemaField("created_at", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("auth_provider", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("full_name", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("avatar_url", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("role_id", "STRING", mode="REQUIRED"),
        ],
        "conversation_history": [
            bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("encrypted_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("user_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("conversation_title", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("created_at", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("updated_at", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("is_active", "BOOLEAN", mode="REQUIRED"),
        ],
        "query_history": [
            bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("encrypted_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("user_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("conversation_master_id", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("query", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("response", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("created_at", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("is_sensitive", "BOOLEAN", mode="REQUIRED"),
        ],
        "audit_logs": [
            bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("encrypted_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("user_id", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("action", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("details", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("ip_address", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("created_at", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("severity", "STRING", mode="REQUIRED"),
        ]
    }
    
    # Create tables
    for table_name, schema in tables_schema.items():
        table_ref = client.dataset(dataset_id).table(table_name)
        
        try:
            client.get_table(table_ref)
            print(f" Table {table_name} already exists")
        except:
            table = bigquery.Table(table_ref, schema=schema)
            table = client.create_table(table)
            print(f" Created table {table_name}")
    
    # Create default roles
    roles_table_ref = client.dataset(dataset_id).table("roles")
    
    # Check if roles exist
    query = f"""
    SELECT COUNT(*) as count FROM `precise-equator-274319.{dataset_id}.roles`
    """
    results = list(client.query(query))
    
    if results[0]['count'] == 0:
        print("Creating default roles...")
        import uuid
        from datetime import datetime, timezone
        
        roles_data = [
            {
                'id': str(uuid.uuid4()),
                'name': 'admin',
                'description': 'Administrator role with full access',
                'created_at': datetime.now(timezone.utc).isoformat()
            },
            {
                'id': str(uuid.uuid4()),
                'name': 'client',
                'description': 'Client role with limited access',
                'created_at': datetime.now(timezone.utc).isoformat()
            }
        ]
        
        errors = client.insert_rows_json(roles_table_ref, roles_data)
        if not errors:
            print(" Default roles created successfully")
        else:
            print(f" Error creating roles: {errors}")
    else:
        print(" Default roles already exist")
    
    print(" BigQuery initialization completed!")

if __name__ == "__main__":
    create_tables()