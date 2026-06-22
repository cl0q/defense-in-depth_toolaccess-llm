"""
Database module for LLM Gateway.
Handles connection management and per-request transaction execution.
"""

import time
import asyncio
from contextlib import contextmanager
from typing import Generator, Dict, Any, Optional
import psycopg2
from psycopg2.pool import SimpleConnectionPool
from psycopg2.extras import RealDictCursor
from fastapi import HTTPException
from .config import get_config

# Global connection pool
_db_pool = None

def init_db_pool():
    """Initialize the database connection pool."""
    global _db_pool
    config = get_config()
    
    # Create connection string for the non-privileged role_app user
    conn_string = (
        f"host={config.db_host} "
        f"port={config.db_port} "
        f"dbname={config.db_name} "
        f"user={config.db_user} "
        f"password={config.db_password}"
    )
    
    # Initialize connection pool (adjust minconn/maxconn as needed)
    _db_pool = SimpleConnectionPool(
        1, 20,  # minconn, maxconn
        conn_string,
        cursor_factory=RealDictCursor
    )

@contextmanager
def get_db_connection() -> Generator[psycopg2.extensions.connection, None, None]:
    """Get a database connection from the pool."""
    if _db_pool is None:
        init_db_pool()
    
    conn = _db_pool.getconn()
    try:
        yield conn
    finally:
        _db_pool.putconn(conn)

def execute_transaction(
    sql_statements: list, 
    params: Optional[list] = None,
    identity: Optional[Dict[str, Any]] = None
) -> list:
    """
    Execute a series of SQL statements within a single transaction.
    Uses the provided identity to set session context (role, tenant, user).
    """
    if params is None:
        params = []
    
    # Get a connection
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            try:
                # Begin transaction
                cur.execute("BEGIN")
                
                # Set session identity from the authenticated identity
                if identity:
                    # Set the role based on identity.role
                    role_map = {
                        "admin": "role_admin",
                        "merchant": "role_merchant", 
                        "customer": "role_customer"
                    }
                    
                    db_role = role_map.get(identity.get("role"), "role_customer")
                    tenant = identity.get("tenant", "")
                    user_id = identity.get("user_id", "")
                    merchant_id = identity.get("merchant_id", "")
                    app_role = identity.get("role", "customer")
                    
                    # Set session context variables
                    cur.execute(
                        "SET LOCAL ROLE %s;",
                        (db_role,)
                    )
                    cur.execute(
                        "SELECT set_config('app.current_tenant', %s, true);",
                        (tenant,)
                    )
                    cur.execute(
                        "SELECT set_config('app.current_user', %s, true);",
                        (user_id,)
                    )
                    cur.execute(
                        "SELECT set_config('app.current_merchant', %s, true);",
                        (merchant_id,)
                    )
                    cur.execute(
                        "SELECT set_config('app.current_role', %s, true);",
                        (app_role,)
                    )
                
                # Execute SQL statements
                results = []
                for sql in sql_statements:
                    if sql.strip():  # Skip empty statements
                        cur.execute(sql, params)
                        if cur.description:  # If it's a SELECT query
                            results.extend(cur.fetchall())
                
                # Commit transaction (this discards SET LOCAL changes)
                cur.execute("COMMIT")
                
                return results
                
            except Exception as e:
                # Rollback on error
                cur.execute("ROLLBACK")
                raise HTTPException(status_code=500, detail=f"Database transaction failed: {str(e)}")