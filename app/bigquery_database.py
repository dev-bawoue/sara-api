#!/usr/bin/env python3
"""
Simplified BigQuery database configuration for SARA API
This version includes better error handling and fallbacks for Python 3.13
"""

import os
import logging
import json
import base64
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import BigQuery with fallback
try:
    from google.cloud import bigquery
    from google.oauth2 import service_account
    import pandas as pd
    BIGQUERY_AVAILABLE = True
    logger.info(" Google Cloud BigQuery libraries imported successfully")
except ImportError as e:
    logger.warning(f"  BigQuery libraries not available: {e}")
    logger.warning("   Falling back to mock implementation for local development")
    BIGQUERY_AVAILABLE = False

# Configuration
PROJECT_ID = os.getenv("PROJECT_ID", "precise-equator-274319")
DATASET_ID = os.getenv("BIGQUERY_DATASET", "sara_dataset")
LOCATION = os.getenv("BIGQUERY_LOCATION", "US")
ENCRYPTION_KEY = os.getenv("ID_ENCRYPTION_KEY", "your-base64-encoded-32-byte-key-here")

class IDEncryption:
    """Handle ID encryption and decryption"""
    
    def __init__(self):
        try:
            if ENCRYPTION_KEY == "your-base64-encoded-32-byte-key-here":
                logger.warning("Using default encryption key - generate a proper key for production!")
                self.cipher = Fernet(Fernet.generate_key())
            else:
                self.cipher = Fernet(ENCRYPTION_KEY.encode())
        except Exception as e:
            logger.error(f"Failed to initialize encryption: {e}")
            self.cipher = Fernet(Fernet.generate_key())
    
    def encrypt_id(self, plain_id: str) -> str:
        """Encrypt an ID"""
        try:
            encrypted = self.cipher.encrypt(plain_id.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return plain_id
    
    def decrypt_id(self, encrypted_id: str) -> str:
        """Decrypt an ID"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_id.encode())
            decrypted = self.cipher.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return encrypted_id

class MockBigQueryClient:
    """Mock BigQuery client for local development when BigQuery is not available"""
    
    def __init__(self):
        self.data_store = {}
        logger.info(" Using mock BigQuery client for local development")
    
    def query(self, sql: str):
        """Mock query method"""
        logger.debug(f"Mock query: {sql}")
        return []
    
    def insert_rows_json(self, table_ref, rows):
        """Mock insert method"""
        table_name = str(table_ref).split('.')[-1]
        if table_name not in self.data_store:
            self.data_store[table_name] = []
        self.data_store[table_name].extend(rows)
        logger.debug(f"Mock insert into {table_name}: {len(rows)} rows")
        return []

class SimplifiedBigQueryDatabase:
    """Simplified BigQuery database manager with better error handling"""
    
    def __init__(self):
        self.project_id = PROJECT_ID
        self.dataset_id = DATASET_ID
        self.location = LOCATION
        self.client = None
        self.id_crypto = IDEncryption()
        self.is_mock = False
        
        self._initialize_client()
        if BIGQUERY_AVAILABLE and not self.is_mock:
            self._setup_database()
    
    def _initialize_client(self):
        """Initialize BigQuery client with fallback to mock"""
        try:
            if not BIGQUERY_AVAILABLE:
                self.client = MockBigQueryClient()
                self.is_mock = True
                return
            
            # Try to use service account key if available
            credentials_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
            if credentials_path and os.path.exists(credentials_path):
                credentials = service_account.Credentials.from_service_account_file(credentials_path)
                self.client = bigquery.Client(credentials=credentials, project=self.project_id)
            else:
                # Use default credentials (for Cloud Run)
                self.client = bigquery.Client(project=self.project_id)
            
            logger.info(f" BigQuery client initialized for project: {self.project_id}")
            
        except Exception as e:
            logger.error(f" Failed to initialize BigQuery client: {e}")
            logger.info(" Falling back to mock client for local development")
            self.client = MockBigQueryClient()
            self.is_mock = True
    
    def _setup_database(self):
        """Setup database (only if real BigQuery is available)"""
        if self.is_mock:
            logger.info(" Skipping database setup for mock client")
            return
        
        try:
            self._ensure_dataset_exists()
            self._ensure_tables_exist()
            logger.info(" Database setup completed")
        except Exception as e:
            logger.error(f" Database setup failed: {e}")
    
    def _ensure_dataset_exists(self):
        """Create dataset if it doesn't exist"""
        if self.is_mock:
            return
        
        try:
            dataset_ref = self.client.dataset(self.dataset_id)
            try:
                self.client.get_dataset(dataset_ref)
                logger.info(f"Dataset {self.dataset_id} already exists")
            except:
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
        if self.is_mock:
            return
        
        tables_sql = {
            "roles": """
                CREATE TABLE IF NOT EXISTS `{project}.{dataset}.roles` (
                    id STRING NOT NULL,
                    name STRING NOT NULL,
                    description STRING,
                    created_at TIMESTAMP NOT NULL
                )
            """,
            "users": """
                CREATE TABLE IF NOT EXISTS `{project}.{dataset}.users` (
                    id STRING NOT NULL,
                    encrypted_id STRING NOT NULL,
                    email STRING NOT NULL,
                    hashed_password STRING,
                    is_active BOOLEAN NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    auth_provider STRING NOT NULL,
                    full_name STRING,
                    avatar_url STRING,
                    role_id STRING NOT NULL
                )
            """,
            "conversation_history": """
                CREATE TABLE IF NOT EXISTS `{project}.{dataset}.conversation_history` (
                    id STRING NOT NULL,
                    encrypted_id STRING NOT NULL,
                    user_id STRING NOT NULL,
                    conversation_title STRING NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN NOT NULL
                )
            """,
            "query_history": """
                CREATE TABLE IF NOT EXISTS `{project}.{dataset}.query_history` (
                    id STRING NOT NULL,
                    encrypted_id STRING NOT NULL,
                    user_id STRING NOT NULL,
                    conversation_master_id STRING,
                    query STRING NOT NULL,
                    response STRING NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    is_sensitive BOOLEAN NOT NULL
                )
            """,
            "audit_logs": """
                CREATE TABLE IF NOT EXISTS `{project}.{dataset}.audit_logs` (
                    id STRING NOT NULL,
                    encrypted_id STRING NOT NULL,
                    user_id STRING,
                    action STRING NOT NULL,
                    details STRING,
                    ip_address STRING,
                    created_at TIMESTAMP NOT NULL,
                    severity STRING NOT NULL
                )
            """
        }
        
        for table_name, sql in tables_sql.items():
            try:
                formatted_sql = sql.format(
                    project=self.project_id,
                    dataset=self.dataset_id
                )
                self.client.query(formatted_sql).result()
                logger.info(f" Table {table_name} ready")
            except Exception as e:
                logger.error(f" Error creating table {table_name}: {e}")
        
        # Initialize default roles
        self._initialize_default_roles()
    
    def _initialize_default_roles(self):
        """Initialize default roles"""
        if self.is_mock:
            return
        
        try:
            # Check if roles exist
            sql = f"SELECT COUNT(*) as count FROM `{self.project_id}.{self.dataset_id}.roles`"
            results = list(self.client.query(sql).result())
            
            if results and results[0].count == 0:
                logger.info("Creating default roles...")
                
                roles = [
                    {
                        'id': self._generate_id(),
                        'name': 'admin',
                        'description': 'Administrator role with full access',
                        'created_at': datetime.now(timezone.utc).isoformat()
                    },
                    {
                        'id': self._generate_id(),
                        'name': 'client', 
                        'description': 'Client role with limited access',
                        'created_at': datetime.now(timezone.utc).isoformat()
                    }
                ]
                
                table_ref = self.client.dataset(self.dataset_id).table('roles')
                errors = self.client.insert_rows_json(table_ref, roles)
                
                if not errors:
                    logger.info(" Default roles created successfully")
                else:
                    logger.error(f" Error creating roles: {errors}")
            
        except Exception as e:
            logger.error(f"Error initializing default roles: {e}")
    
    def _generate_id(self) -> str:
        """Generate unique ID"""
        import uuid
        return str(uuid.uuid4())
    
    def test_connection(self) -> bool:
        """Test database connection"""
        try:
            if self.is_mock:
                return True
            
            sql = "SELECT 1 as test"
            result = list(self.client.query(sql).result())
            return len(result) > 0
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
    
    def query(self, sql: str, parameters: Optional[Dict] = None) -> List[Dict]:
        """Execute a query"""
        if self.is_mock:
            return []
        
        try:
            if parameters:
                job_config = bigquery.QueryJobConfig()
                query_parameters = []
                
                for key, value in parameters.items():
                    if isinstance(value, str):
                        param = bigquery.ScalarQueryParameter(key, "STRING", value)
                    elif isinstance(value, int):
                        param = bigquery.ScalarQueryParameter(key, "INTEGER", value)
                    elif isinstance(value, bool):
                        param = bigquery.ScalarQueryParameter(key, "BOOLEAN", value)
                    elif isinstance(value, datetime):
                        param = bigquery.ScalarQueryParameter(key, "TIMESTAMP", value)
                    else:
                        param = bigquery.ScalarQueryParameter(key, "STRING", str(value))
                    
                    query_parameters.append(param)
                
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
            logger.error(f"Query error: {e}")
            return []
    
    def insert_row(self, table_name: str, data: Dict[str, Any]) -> str:
        """Insert a row"""
        try:
            # Generate ID if not present
            if 'id' not in data:
                data['id'] = self._generate_id()
            
            # Add encrypted ID for all tables except roles
            if table_name != 'roles' and 'encrypted_id' not in data:
                data['encrypted_id'] = self.id_crypto.encrypt_id(data['id'])
            
            # Add timestamp if not present
            if 'created_at' not in data:
                data['created_at'] = datetime.now(timezone.utc).isoformat()
            
            # Convert datetime objects to ISO strings
            for key, value in data.items():
                if isinstance(value, datetime):
                    data[key] = value.isoformat()
            
            if self.is_mock:
                logger.debug(f"Mock insert into {table_name}")
                return data['id']
            
            table_ref = self.client.dataset(self.dataset_id).table(table_name)
            errors = self.client.insert_rows_json(table_ref, [data])
            
            if errors:
                logger.error(f"Insert errors: {errors}")
                raise Exception(f"Insert failed: {errors}")
            
            return data['id']
            
        except Exception as e:
            logger.error(f"Insert error: {e}")
            raise
    
    def update_row(self, table_name: str, record_id: str, data: Dict[str, Any]):
        """Update a row"""
        if self.is_mock:
            logger.debug(f"Mock update in {table_name}")
            return
        
        try:
            data['updated_at'] = datetime.now(timezone.utc)
            
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
            
        except Exception as e:
            logger.error(f"Update error: {e}")
            raise
    
    def get_table_full_name(self, table_name: str) -> str:
        """Get full table name for queries"""
        return f"`{self.project_id}.{self.dataset_id}.{table_name}`"

# Global database instance
_bq_db = None

def get_bq_db():
    """Get BigQuery database instance (singleton pattern)"""
    global _bq_db
    if _bq_db is None:
        _bq_db = SimplifiedBigQueryDatabase()
    return _bq_db

# Export main components
__all__ = [
    'SimplifiedBigQueryDatabase',
    'get_bq_db',
    'IDEncryption',
    'BIGQUERY_AVAILABLE'
]