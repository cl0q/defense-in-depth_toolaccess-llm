"""
Database module for LLM Gateway.
Handles connection management and per-request transaction execution.
"""

import logging
import time
from contextlib import contextmanager
from typing import Generator, Dict, Any, Optional, List
import psycopg2
from psycopg2 import sql
from psycopg2.pool import SimpleConnectionPool
from psycopg2.extras import RealDictCursor
from fastapi import HTTPException
from .config import get_config

# Global connection pool
_db_pool = None
logger = logging.getLogger(__name__)

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

    _assert_non_privileged_connection_role()


def _assert_non_privileged_connection_role() -> None:
    """Fail fast if the gateway connects as a privileged or bypass-RLS role."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT r.rolname, r.rolsuper, r.rolbypassrls
                FROM pg_roles r
                WHERE r.rolname = current_user
                """
            )
            role_row = cur.fetchone()

    if not role_row:
        raise RuntimeError("Unable to resolve current DB role for gateway connection")

    if role_row["rolsuper"] or role_row["rolbypassrls"]:
        raise RuntimeError(
            "Refusing to start gateway with privileged DB role "
            f"{role_row['rolname']} (rolsuper={role_row['rolsuper']}, "
            f"rolbypassrls={role_row['rolbypassrls']})"
        )

    logger.info("Gateway DB role verified: %s (non-superuser, no bypassrls)", role_row["rolname"])

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
    sql_statements: List[str],
    params: Optional[List[Any]] = None,
    identity: Optional[Dict[str, Any]] = None,
    trace_id: Optional[str] = None,
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
                    cur.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(db_role)))
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
                    if trace_id:
                        cur.execute(
                            "SELECT set_config('application_name', %s, true);",
                            (trace_id,)
                        )
                    
                    logger.info(
                        "DB session identity set role=%s tenant=%s user=%s merchant=%s trace_id=%s",
                        db_role,
                        tenant,
                        user_id,
                        merchant_id,
                        trace_id,
                    )
                
                # Execute SQL statements
                results = []
                for stmt in sql_statements:
                    if stmt.strip():  # Skip empty statements
                        sql_start_time = time.time()
                        cur.execute(stmt, params)
                        sql_end_time = time.time()
                        sql_duration = (sql_end_time - sql_start_time) * 1000
                        logger.info("SQL execution time: %.2fms for query: %s...", sql_duration, stmt[:50])
                        if cur.description:  # If it's a SELECT query
                            results.extend(cur.fetchall())
                
                # Commit transaction (this discards SET LOCAL changes)
                cur.execute("COMMIT")
                
                return results
                
            except Exception as e:
                # Rollback on error
                cur.execute("ROLLBACK")
                raise HTTPException(status_code=500, detail=f"Database transaction failed: {str(e)}")