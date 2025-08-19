"""
CRUD operations for BigQuery database
Updated with role-based access control and ID encryption
"""

from typing import List, Optional, Dict, Any
from datetime import date, datetime, timezone, timedelta
import re
import logging

from app.bigquery_database import get_bq_db
from app.bigquery_models import User, ConversationHistory, QueryHistory, AuditLog, Role
from app import schemas, auth

logger = logging.getLogger(__name__)

class SensitiveDataScanner:
    """Scanner for sensitive data patterns."""
    
    SENSITIVE_PATTERNS = [
        r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # Credit card
        r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b',  # SSN
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone number
    ]
    
    @classmethod
    def contains_sensitive_data(cls, text: str) -> bool:
        """Check if text contains sensitive data."""
        for pattern in cls.SENSITIVE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

# Role CRUD operations
def get_role_by_name(role_name: str) -> Optional[Role]:
    """Get role by name."""
    try:
        bq_db = get_bq_db()
        sql = f"""
        SELECT * FROM {bq_db.get_table_full_name('roles')}
        WHERE name = @role_name
        LIMIT 1
        """
        
        results = bq_db.query(sql, {'role_name': role_name})
        
        if results:
            return Role.from_dict(results[0])
        return None
        
    except Exception as e:
        logger.error(f"Error getting role by name {role_name}: {e}")
        return None

def get_role_by_id(role_id: str) -> Optional[Role]:
    """Get role by ID."""
    try:
        bq_db = get_bq_db()
        sql = f"""
        SELECT * FROM {bq_db.get_table_full_name('roles')}
        WHERE id = @role_id
        LIMIT 1
        """
        
        results = bq_db.query(sql, {'role_id': role_id})
        
        if results:
            return Role.from_dict(results[0])
        return None
        
    except Exception as e:
        logger.error(f"Error getting role by ID {role_id}: {e}")
        return None

def get_default_client_role() -> Optional[Role]:
    """Get the default client role."""
    return get_role_by_name('client')

def get_admin_role() -> Optional[Role]:
    """Get the admin role."""
    return get_role_by_name('admin')

# User CRUD operations
def get_user_by_email(email: str) -> Optional[User]:
    """Get user by email."""
    try:
        bq_db = get_bq_db()
        sql = f"""
        SELECT u.*, r.name as role_name FROM {bq_db.get_table_full_name('users')} u
        LEFT JOIN {bq_db.get_table_full_name('roles')} r ON u.role_id = r.id
        WHERE u.email = @email
        LIMIT 1
        """
        
        results = bq_db.query(sql, {'email': email})
        
        if results:
            user_data = results[0]
            # Add role name to user data
            user_data['role_name'] = user_data.get('role_name')
            return User.from_dict(user_data)
        return None
        
    except Exception as e:
        logger.error(f"Error getting user by email {email}: {e}")
        return None

def get_user_by_id(user_id: str) -> Optional[User]:
    """Get user by ID."""
    try:
        bq_db = get_bq_db()
        sql = f"""
        SELECT u.*, r.name as role_name FROM {bq_db.get_table_full_name('users')} u
        LEFT JOIN {bq_db.get_table_full_name('roles')} r ON u.role_id = r.id
        WHERE u.id = @user_id
        LIMIT 1
        """
        
        results = bq_db.query(sql, {'user_id': user_id})
        
        if results:
            user_data = results[0]
            user_data['role_name'] = user_data.get('role_name')
            return User.from_dict(user_data)
        return None
        
    except Exception as e:
        logger.error(f"Error getting user by ID {user_id}: {e}")
        return None

def create_user(user: schemas.UserCreate) -> User:
    """Create new user - handles both email/password and OAuth users."""
    try:
        bq_db = get_bq_db()
        
        # Get default client role
        client_role = get_default_client_role()
        if not client_role:
            raise Exception("Default client role not found")
        
        # For OAuth users, password will be None
        hashed_password = None
        if user.password:
            hashed_password = auth.get_password_hash(user.password)
        
        new_user = User.create(
            email=user.email,
            role_id=client_role.id,
            hashed_password=hashed_password,
            auth_provider=user.auth_provider or "email",
            full_name=user.full_name
        )
        
        bq_db.insert_row('users', new_user.to_dict())
        
        logger.info(f"Created user: {user.email}")
        return new_user
        
    except Exception as e:
        logger.error(f"Error creating user {user.email}: {e}")
        raise

def create_admin_user(user: schemas.UserCreate) -> User:
    """Create new admin user."""
    try:
        bq_db = get_bq_db()
        
        # Get admin role
        admin_role = get_admin_role()
        if not admin_role:
            raise Exception("Admin role not found")
        
        # Hash password
        hashed_password = None
        if user.password:
            hashed_password = auth.get_password_hash(user.password)
        
        new_user = User.create(
            email=user.email,
            role_id=admin_role.id,
            hashed_password=hashed_password,
            auth_provider=user.auth_provider or "email",
            full_name=user.full_name
        )
        
        bq_db.insert_row('users', new_user.to_dict())
        
        logger.info(f"Created admin user: {user.email}")
        return new_user
        
    except Exception as e:
        logger.error(f"Error creating admin user {user.email}: {e}")
        raise

def create_oauth_user(email: str, full_name: str = None, provider: str = "google") -> User:
    """Create a new OAuth user."""
    try:
        bq_db = get_bq_db()
        
        # Get default client role
        client_role = get_default_client_role()
        if not client_role:
            raise Exception("Default client role not found")
        
        new_user = User.create(
            email=email,
            role_id=client_role.id,
            hashed_password=None,  # OAuth users don't have passwords
            auth_provider=provider,
            full_name=full_name
        )
        
        bq_db.insert_row('users', new_user.to_dict())
        
        logger.info(f"Created OAuth user: {email}")
        return new_user
        
    except Exception as e:
        logger.error(f"Error creating OAuth user {email}: {e}")
        raise

def is_user_admin(user: User) -> bool:
    """Check if user has admin role."""
    try:
        role = get_role_by_id(user.role_id)
        return role and role.name == 'admin'
    except Exception as e:
        logger.error(f"Error checking if user is admin: {e}")
        return False

# Conversation CRUD operations
def create_conversation(user_id: str, title: str) -> ConversationHistory:
    """Create new conversation."""
    try:
        bq_db = get_bq_db()
        
        conversation = ConversationHistory.create(
            user_id=user_id,
            conversation_title=title
        )
        
        bq_db.insert_row('conversation_history', conversation.to_dict())
        
        logger.info(f"Created conversation: {title} for user {user_id}")
        return conversation
        
    except Exception as e:
        logger.error(f"Error creating conversation for user {user_id}: {e}")
        raise

def get_user_conversations(user_id: str, skip: int = 0, limit: int = 100) -> List[Dict]:
    """Get user's conversations with query count."""
    try:
        bq_db = get_bq_db()
        
        sql = f"""
        SELECT 
            c.*,
            COUNTIF(q.id IS NOT NULL) as query_count
        FROM {bq_db.get_table_full_name('conversation_history')} c
        LEFT JOIN {bq_db.get_table_full_name('query_history')} q 
            ON c.id = q.conversation_master_id
        WHERE c.user_id = @user_id AND c.is_active = true
        GROUP BY c.id, c.encrypted_id, c.user_id, c.conversation_title, c.created_at, c.updated_at, c.is_active
        ORDER BY c.updated_at DESC
        LIMIT @limit OFFSET @skip
        """
        
        results = bq_db.query(sql, {
            'user_id': user_id,
            'skip': skip,
            'limit': limit
        })
        
        # Convert results to the expected format
        conversations = []
        for row in results:
            conversations.append({
                "id": row['encrypted_id'],  # Return encrypted ID
                "conversation_title": row['conversation_title'],
                "created_at": row['created_at'],
                "updated_at": row['updated_at'],
                "is_active": row['is_active'],
                "query_count": row['query_count'] or 0
            })
        
        return conversations
        
    except Exception as e:
        logger.error(f"Error getting conversations for user {user_id}: {e}")
        return []

def get_conversation_count(user_id: str) -> int:
    """Get total conversation count for user."""
    try:
        bq_db = get_bq_db()
        
        sql = f"""
        SELECT COUNT(*) as count 
        FROM {bq_db.get_table_full_name('conversation_history')}
        WHERE user_id = @user_id AND is_active = true
        """
        
        results = bq_db.query(sql, {'user_id': user_id})
        return results[0]['count'] if results else 0
        
    except Exception as e:
        logger.error(f"Error getting conversation count for user {user_id}: {e}")
        return 0

def get_conversation_queries(conversation_id: str, skip: int = 0, limit: int = 100) -> List[QueryHistory]:
    """Get queries for a specific conversation."""
    try:
        bq_db = get_bq_db()
        
        # Try to decrypt the conversation ID first
        try:
            decrypted_id = bq_db.id_crypto.decrypt_id(conversation_id)
        except:
            decrypted_id = conversation_id  # Fallback to original ID
        
        sql = f"""
        SELECT * FROM {bq_db.get_table_full_name('query_history')}
        WHERE conversation_master_id = @conversation_id
        ORDER BY created_at ASC
        LIMIT @limit OFFSET @skip
        """
        
        results = bq_db.query(sql, {
            'conversation_id': decrypted_id,
            'skip': skip,
            'limit': limit
        })
        
        return [QueryHistory.from_dict(row) for row in results]
        
    except Exception as e:
        logger.error(f"Error getting queries for conversation {conversation_id}: {e}")
        return []

def update_conversation_title(conversation_id: str, title: str):
    """Update conversation title."""
    try:
        bq_db = get_bq_db()
        
        # Try to decrypt the conversation ID first
        try:
            decrypted_id = bq_db.id_crypto.decrypt_id(conversation_id)
        except:
            decrypted_id = conversation_id  # Fallback to original ID
        
        bq_db.update_row('conversation_history', decrypted_id, {
            'conversation_title': title
        })
        
        logger.info(f"Updated conversation {conversation_id} title to: {title}")
        
    except Exception as e:
        logger.error(f"Error updating conversation {conversation_id}: {e}")
        raise

def delete_conversation(conversation_id: str, user_id: str):
    """Soft delete conversation."""
    try:
        bq_db = get_bq_db()
        
        # Try to decrypt the conversation ID first
        try:
            decrypted_id = bq_db.id_crypto.decrypt_id(conversation_id)
        except:
            decrypted_id = conversation_id  # Fallback to original ID
        
        # Soft delete conversation
        bq_db.update_row('conversation_history', decrypted_id, {
            'is_active': False
        })
        
        logger.info(f"Deleted conversation {conversation_id} for user {user_id}")
        
    except Exception as e:
        logger.error(f"Error deleting conversation {conversation_id}: {e}")
        raise

# Query CRUD operations
def create_query(user_id: str, query: str, response: str, conversation_master_id: str) -> QueryHistory:
    """Create new query history entry."""
    try:
        bq_db = get_bq_db()
        
        # Try to decrypt the conversation ID if it's encrypted
        try:
            decrypted_conversation_id = bq_db.id_crypto.decrypt_id(conversation_master_id)
        except:
            decrypted_conversation_id = conversation_master_id  # Fallback to original ID
        
        is_sensitive = SensitiveDataScanner.contains_sensitive_data(f"{query} {response}")
        
        query_history = QueryHistory.create(
            user_id=user_id,
            query=query,
            response=response,
            conversation_master_id=decrypted_conversation_id,
            is_sensitive=is_sensitive
        )
        
        bq_db.insert_row('query_history', query_history.to_dict())
        
        # Update conversation's updated_at timestamp
        bq_db.update_row('conversation_history', decrypted_conversation_id, {
            'updated_at': datetime.now(timezone.utc)
        })
        
        logger.info(f"Created query for user {user_id}")
        return query_history
        
    except Exception as e:
        logger.error(f"Error creating query for user {user_id}: {e}")
        raise

def get_user_queries(user_id: str, skip: int = 0, limit: int = 100) -> List[QueryHistory]:
    """Get user's query history."""
    try:
        bq_db = get_bq_db()
        
        sql = f"""
        SELECT * FROM {bq_db.get_table_full_name('query_history')}
        WHERE user_id = @user_id
        ORDER BY created_at DESC
        LIMIT @limit OFFSET @skip
        """
        
        results = bq_db.query(sql, {
            'user_id': user_id,
            'skip': skip,
            'limit': limit
        })
        
        return [QueryHistory.from_dict(row) for row in results]
        
    except Exception as e:
        logger.error(f"Error getting queries for user {user_id}: {e}")
        return []

def get_query_count(user_id: str) -> int:
    """Get total query count for user."""
    try:
        bq_db = get_bq_db()
        
        sql = f"""
        SELECT COUNT(*) as count 
        FROM {bq_db.get_table_full_name('query_history')}
        WHERE user_id = @user_id
        """
        
        results = bq_db.query(sql, {'user_id': user_id})
        return results[0]['count'] if results else 0
        
    except Exception as e:
        logger.error(f"Error getting query count for user {user_id}: {e}")
        return 0

def get_daily_query_count(user_id: str, target_date: date = None) -> int:
    """Get query count for a specific date."""
    try:
        bq_db = get_bq_db()
        
        if target_date is None:
            target_date = date.today()
        
        # Convert date to datetime range
        start_datetime = datetime.combine(target_date, datetime.min.time()).replace(tzinfo=timezone.utc)
        end_datetime = datetime.combine(target_date, datetime.max.time()).replace(tzinfo=timezone.utc)
        
        sql = f"""
        SELECT COUNT(*) as count 
        FROM {bq_db.get_table_full_name('query_history')}
        WHERE user_id = @user_id 
        AND created_at >= @start_date 
        AND created_at <= @end_date
        """
        
        results = bq_db.query(sql, {
            'user_id': user_id,
            'start_date': start_datetime,
            'end_date': end_datetime
        })
        
        return results[0]['count'] if results else 0
        
    except Exception as e:
        logger.error(f"Error getting daily query count for user {user_id}: {e}")
        return 0

# Audit log CRUD operations
def create_audit_log(
    action: str, 
    details: Optional[str] = None, 
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    severity: str = "INFO"
) -> AuditLog:
    """Create audit log entry."""
    try:
        bq_db = get_bq_db()
        
        audit_log = AuditLog.create(
            action=action,
            user_id=user_id,
            details=details,
            ip_address=ip_address,
            severity=severity
        )
        
        bq_db.insert_row('audit_logs', audit_log.to_dict())
        
        logger.debug(f"Created audit log: {action}")
        return audit_log
        
    except Exception as e:
        logger.error(f"Error creating audit log: {e}")
        raise

def get_audit_logs(skip: int = 0, limit: int = 100) -> List[AuditLog]:
    """Get audit logs (admin only)."""
    try:
        bq_db = get_bq_db()
        
        sql = f"""
        SELECT * FROM {bq_db.get_table_full_name('audit_logs')}
        ORDER BY created_at DESC
        LIMIT @limit OFFSET @skip
        """
        
        results = bq_db.query(sql, {
            'skip': skip,
            'limit': limit
        })
        
        return [AuditLog.from_dict(row) for row in results]
        
    except Exception as e:
        logger.error(f"Error getting audit logs: {e}")
        return []

# Admin functions
def get_all_users(skip: int = 0, limit: int = 50) -> List[Dict]:
    """Get all users with query counts (admin only)."""
    try:
        bq_db = get_bq_db()
        
        sql = f"""
        SELECT 
            u.*,
            r.name as role_name,
            COUNTIF(q.id IS NOT NULL) as query_count
        FROM {bq_db.get_table_full_name('users')} u
        LEFT JOIN {bq_db.get_table_full_name('roles')} r ON u.role_id = r.id
        LEFT JOIN {bq_db.get_table_full_name('query_history')} q 
            ON u.id = q.user_id
        GROUP BY u.id, u.encrypted_id, u.email, u.hashed_password, u.is_active, u.created_at, u.auth_provider, u.full_name, u.avatar_url, u.role_id, r.name
        ORDER BY u.created_at DESC
        LIMIT @limit OFFSET @skip
        """
        
        results = bq_db.query(sql, {
            'skip': skip,
            'limit': limit
        })
        
        users = []
        for row in results:
            users.append({
                "id": row['encrypted_id'],  # Return encrypted ID
                "email": row['email'],
                "is_active": row['is_active'],
                "created_at": row['created_at'],
                "role_name": row['role_name'],
                "query_count": row['query_count'] or 0
            })
        
        return users
        
    except Exception as e:
        logger.error(f"Error getting all users: {e}")
        return []

def get_system_stats() -> Dict[str, Any]:
    """Get system statistics (admin only)."""
    try:
        bq_db = get_bq_db()
        
        today = date.today()
        yesterday = today - timedelta(days=1)
        week_ago = today - timedelta(days=7)
        
        # Convert to datetime
        today_start = datetime.combine(today, datetime.min.time()).replace(tzinfo=timezone.utc)
        yesterday_start = datetime.combine(yesterday, datetime.min.time()).replace(tzinfo=timezone.utc)
        week_ago_start = datetime.combine(week_ago, datetime.min.time()).replace(tzinfo=timezone.utc)
        
        # Total counts
        total_users_sql = f"SELECT COUNT(*) as count FROM {bq_db.get_table_full_name('users')}"
        total_queries_sql = f"SELECT COUNT(*) as count FROM {bq_db.get_table_full_name('query_history')}"
        
        # Today's stats
        queries_today_sql = f"""
        SELECT COUNT(*) as count FROM {bq_db.get_table_full_name('query_history')}
        WHERE created_at >= @today_start
        """
        
        # Weekly stats
        queries_week_sql = f"""
        SELECT COUNT(*) as count FROM {bq_db.get_table_full_name('query_history')}
        WHERE created_at >= @week_ago_start
        """
        
        # Sensitive data alerts
        sensitive_queries_sql = f"""
        SELECT COUNT(*) as count FROM {bq_db.get_table_full_name('query_history')}
        WHERE is_sensitive = true
        """
        
        # Failed login attempts (last 24h)
        failed_logins_sql = f"""
        SELECT COUNT(*) as count FROM {bq_db.get_table_full_name('audit_logs')}
        WHERE action = 'LOGIN_FAILED' AND created_at >= @yesterday_start
        """
        
        # Execute queries
        total_users = bq_db.query(total_users_sql)[0]['count']
        total_queries = bq_db.query(total_queries_sql)[0]['count']
        queries_today = bq_db.query(queries_today_sql, {'today_start': today_start})[0]['count']
        queries_week = bq_db.query(queries_week_sql, {'week_ago_start': week_ago_start})[0]['count']
        sensitive_queries = bq_db.query(sensitive_queries_sql)[0]['count']
        failed_logins = bq_db.query(failed_logins_sql, {'yesterday_start': yesterday_start})[0]['count']
        
        return {
            "total_users": total_users,
            "total_queries": total_queries,
            "queries_today": queries_today,
            "queries_this_week": queries_week,
            "sensitive_queries_total": sensitive_queries,
            "failed_logins_24h": failed_logins
        }
        
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return {
            "total_users": 0,
            "total_queries": 0,
            "queries_today": 0,
            "queries_this_week": 0,
            "sensitive_queries_total": 0,
            "failed_logins_24h": 0
        }

def toggle_user_status(user_id: str) -> bool:
    """Toggle user active status (admin only)."""
    try:
        bq_db = get_bq_db()
        
        # Try to decrypt the user ID first
        try:
            decrypted_id = bq_db.id_crypto.decrypt_id(user_id)
        except:
            decrypted_id = user_id  # Fallback to original ID
        
        # First get current status
        sql = f"""
        SELECT is_active FROM {bq_db.get_table_full_name('users')}
        WHERE id = @user_id
        """
        
        results = bq_db.query(sql, {'user_id': decrypted_id})
        if not results:
            raise Exception("User not found")
        
        current_status = results[0]['is_active']
        new_status = not current_status
        
        # Update status
        bq_db.update_row('users', decrypted_id, {'is_active': new_status})
        
        logger.info(f"Toggled user {user_id} status to: {new_status}")
        return new_status
        
    except Exception as e:
        logger.error(f"Error toggling user status for {user_id}: {e}")
        raise

def get_conversation_by_id(conversation_id: str, user_id: str) -> Optional[ConversationHistory]:
    """Get conversation by ID for a specific user."""
    try:
        bq_db = get_bq_db()
        
        # Try to decrypt the conversation ID first
        try:
            decrypted_id = bq_db.id_crypto.decrypt_id(conversation_id)
        except:
            decrypted_id = conversation_id  # Fallback to original ID
        
        sql = f"""
        SELECT * FROM {bq_db.get_table_full_name('conversation_history')}
        WHERE id = @conversation_id AND user_id = @user_id
        LIMIT 1
        """
        
        results = bq_db.query(sql, {
            'conversation_id': decrypted_id,
            'user_id': user_id
        })

        
        
        if results:
            return ConversationHistory.from_dict(results[0])
        return None
        
    except Exception as e:
        logger.error(f"Error getting conversation {conversation_id}: {e}")
        return None