#!/usr/bin/env python3
"""
BigQuery database configuration for SARA API
Updated with ID encryption and role-based access control
"""

import os
import logging
from google.cloud import bigquery
from google.oauth2 import service_account
import pandas as pd
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import json
import base64
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# BigQuery configuration
PROJECT_ID = os.getenv("PROJECT_ID", "precise-equator-274319")
DATASET_ID = os.getenv("BIGQUERY_DATASET", "sara_dataset")
LOCATION = os.getenv("BIGQUERY_LOCATION", "US")

# ID encryption key - generate a consistent key for the project
ENCRYPTION_KEY = os.getenv("ID_ENCRYPTION_KEY", "your-base64-encoded-32-byte-key-here")

class IDEncryption:
    """Handle ID encryption and decryption"""
    
    def __init__(self):
        try:
            # If no key is provided, generate one (for development)
            if ENCRYPTION_KEY == "your-base64-encoded-32-byte-key-here":
                logger.warning("Using default encryption key - generate a proper key for production!")
                self.cipher = Fernet(Fernet.generate_key())
            else:
                self.cipher = Fernet(ENCRYPTION_KEY.encode())
        except Exception as e:
            logger.error(f"Failed to initialize encryption: {e}")
            # Fallback to a generated key
            self.cipher = Fernet(Fernet.generate_key())
    
    def encrypt_id(self, plain_id: str) -> str:
        """Encrypt an ID"""
        try:
            encrypted = self.cipher.encrypt(plain_id.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return plain_id  # Fallback to plain ID
    
    def decrypt_id(self, encrypted_id: str) -> str:
        """Decrypt an ID"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_id.encode())
            decrypted = self.cipher.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return encrypted_id  # Fallback to assuming it's already decrypted

class BigQueryDatabase:
    """BigQuery database manager for SARA API with ID encryption and roles"""
    
    def __init__(self):
        self.project_id = PROJECT_ID
        self.dataset_id = DATASET_ID
        self.location = LOCATION
        self.client = None
        self.id_crypto = IDEncryption()
        self._initialize_client()
        self._ensure_dataset_exists()
        self._ensure_tables_exist()
    
    def _initialize_client(self):
        """Initialize BigQuery client"""
        try:
            # Try to use service account key if available
            credentials_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
            if credentials_path and os.path.exists(credentials_path):
                credentials = service_account.Credentials.from_service_account_file(credentials_path)
                self.client = bigquery.Client(credentials=credentials, project=self.project_id)
            else:
                # Use default credentials (for Cloud Run)
                self.client = bigquery.Client(project=self.project_id)
            
            logger.info(f"BigQuery client initialized for project: {self.project_id}")
            
        except Exception as e:
            logger.error(f"Failed to initialize BigQuery client: {e}")
            raise
    
    def _ensure_dataset_exists(self):
        """Create dataset if it doesn't exist"""
        try:
            dataset_ref = self.client.dataset(self.dataset_id)
            
            try:
                self.client.get_dataset(dataset_ref)
                logger.info(f"Dataset {self.dataset_id} already exists")
            except:
                # Create dataset
                dataset = bigquery.Dataset(dataset_ref)
                dataset.location = self.location
                dataset.description = "SARA API data storage"
                
                dataset = self.client.create_dataset(dataset)
                logger.info(f"Created dataset {self.dataset_id}")
                
        except Exception as e:
            logger.error(f"Error ensuring dataset exists: {e}")
            raise
    
    def _ensure_tables_exist(self):
        """Create tables if they don't exist"""
        try:
            tables = {
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
            
            for table_name, schema in tables.items():
                self._create_table_if_not_exists(table_name, schema)
            
            # Initialize default roles
            self._initialize_default_roles()
                
        except Exception as e:
            logger.error(f"Error ensuring tables exist: {e}")
            raise
    
    def _create_table_if_not_exists(self, table_name: str, schema: List[bigquery.SchemaField]):
        """Create a table if it doesn't exist"""
        try:
            table_ref = self.client.dataset(self.dataset_id).table(table_name)
            
            try:
                self.client.get_table(table_ref)
                logger.info(f"Table {table_name} already exists")
            except:
                # Create table
                table = bigquery.Table(table_ref, schema=schema)
                table.description = f"SARA API {table_name} table"
                
                table = self.client.create_table(table)
                logger.info(f"Created table {table_name}")
                
        except Exception as e:
            logger.error(f"Error creating table {table_name}: {e}")
            raise
    
    def _initialize_default_roles(self):
        """Initialize default admin and client roles"""
        try:
            # Check if roles already exist
            sql = f"SELECT COUNT(*) as count FROM {self.get_table_full_name('roles')}"
            results = self.query(sql)
            
            if results and results[0]['count'] == 0:
                logger.info("Initializing default roles...")
                
                # Create admin role
                admin_role = {
                    'id': self._generate_id(),
                    'name': 'admin',
                    'description': 'Administrator role with full access',
                    'created_at': self._get_current_timestamp()
                }
                self.insert_row('roles', admin_role)
                
                # Create client role
                client_role = {
                    'id': self._generate_id(),
                    'name': 'client',
                    'description': 'Client role with limited access',
                    'created_at': self._get_current_timestamp()
                }
                self.insert_row('roles', client_role)
                
                logger.info("✅ Default roles created successfully")
            else:
                logger.info("Default roles already exist")
                
        except Exception as e:
            logger.error(f"Error initializing default roles: {e}")
    
    def _generate_id(self) -> str:
        """Generate unique ID for records"""
        import uuid
        return str(uuid.uuid4())
    
    def _get_current_timestamp(self) -> datetime:
        """Get current UTC timestamp"""
        return datetime.now(timezone.utc)
    
    def get_role_by_name(self, role_name: str) -> Optional[Dict]:
        """Get role by name"""
        try:
            sql = f"""
            SELECT * FROM {self.get_table_full_name('roles')}
            WHERE name = @role_name
            LIMIT 1
            """
            results = self.query(sql, {'role_name': role_name})
            return results[0] if results else None
        except Exception as e:
            logger.error(f"Error getting role by name {role_name}: {e}")
            return None
    
    def insert_row(self, table_name: str, data: Dict[str, Any]) -> str:
        """Insert a row into BigQuery table with ID encryption"""
        try:
            table_ref = self.client.dataset(self.dataset_id).table(table_name)
            
            # Add ID and timestamp if not present
            if 'id' not in data:
                data['id'] = self._generate_id()
            
            # Add encrypted ID for all tables except roles
            if table_name != 'roles' and 'encrypted_id' not in data:
                data['encrypted_id'] = self.id_crypto.encrypt_id(data['id'])
            
            if 'created_at' not in data:
                data['created_at'] = self._get_current_timestamp()
            
            # Convert datetime objects to strings
            for key, value in data.items():
                if isinstance(value, datetime):
                    data[key] = value.isoformat()
            
            errors = self.client.insert_rows_json(table_ref, [data])
            
            if errors:
                logger.error(f"Error inserting row into {table_name}: {errors}")
                raise Exception(f"Insert failed: {errors}")
            
            logger.debug(f"Inserted row into {table_name} with ID: {data['id']}")
            return data['id']
            
        except Exception as e:
            logger.error(f"Error inserting row into {table_name}: {e}")
            raise
    
    def query(self, sql: str, parameters: Optional[Dict] = None) -> List[Dict]:
        """Execute a BigQuery SQL query"""
        try:
            if parameters:
                # Configure query parameters
                job_config = bigquery.QueryJobConfig()
                query_parameters = []
                
                for key, value in parameters.items():
                    if isinstance(value, str):
                        param_type = bigquery.ScalarQueryParameter(key, "STRING", value)
                    elif isinstance(value, int):
                        param_type = bigquery.ScalarQueryParameter(key, "INTEGER", value)
                    elif isinstance(value, bool):
                        param_type = bigquery.ScalarQueryParameter(key, "BOOLEAN", value)
                    elif isinstance(value, datetime):
                        param_type = bigquery.ScalarQueryParameter(key, "TIMESTAMP", value)
                    else:
                        param_type = bigquery.ScalarQueryParameter(key, "STRING", str(value))
                    
                    query_parameters.append(param_type)
                
                job_config.query_parameters = query_parameters
                query_job = self.client.query(sql, job_config=job_config)
            else:
                query_job = self.client.query(sql)
            
            results = query_job.result()
            
            # Convert to list of dictionaries
            rows = []
            for row in results:
                row_dict = {}
                for key, value in row.items():
                    if isinstance(value, datetime):
                        row_dict[key] = value.isoformat()
                    else:
                        row_dict[key] = value
                rows.append(row_dict)
            
            return rows
            
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            logger.error(f"SQL: {sql}")
            raise
    
    def update_row(self, table_name: str, record_id: str, data: Dict[str, Any]):
        """Update a row in BigQuery table (using MERGE)"""
        try:
            # Add updated_at timestamp
            data['updated_at'] = self._get_current_timestamp()
            
            # Build SET clause
            set_clauses = []
            parameters = {'record_id': record_id}
            
            for key, value in data.items():
                set_clauses.append(f"{key} = @{key}")
                parameters[key] = value
            
            set_clause = ", ".join(set_clauses)
            
            sql = f"""
            UPDATE `{self.project_id}.{self.dataset_id}.{table_name}`
            SET {set_clause}
            WHERE id = @record_id
            """
            
            self.query(sql, parameters)
            logger.debug(f"Updated row {record_id} in {table_name}")
            
        except Exception as e:
            logger.error(f"Error updating row {record_id} in {table_name}: {e}")
            raise
    
    def delete_row(self, table_name: str, record_id: str):
        """Delete a row from BigQuery table"""
        try:
            sql = f"""
            DELETE FROM `{self.project_id}.{self.dataset_id}.{table_name}`
            WHERE id = @record_id
            """
            
            self.query(sql, {'record_id': record_id})
            logger.debug(f"Deleted row {record_id} from {table_name}")
            
        except Exception as e:
            logger.error(f"Error deleting row {record_id} from {table_name}: {e}")
            raise
    
    def get_table_full_name(self, table_name: str) -> str:
        """Get full table name for queries"""
        return f"`{self.project_id}.{self.dataset_id}.{table_name}`"
    
    def test_connection(self) -> bool:
        """Test BigQuery connection"""
        try:
            # Try a simple query
            sql = "SELECT 1 as test"
            result = self.query(sql)
            return len(result) > 0
        except Exception as e:
            logger.error(f"BigQuery connection test failed: {e}")
            return False

# Global BigQuery instance
bq_db = BigQueryDatabase()

def get_bq_db():
    """Get BigQuery database instance"""
    return bq_db

# Export main components
__all__ = [
    'BigQueryDatabase',
    'bq_db',
    'get_bq_db',
    'IDEncryption'
]