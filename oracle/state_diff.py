"""
State diff detection for Oracle module.
Compares database states before and after operations to detect unauthorized writes.
"""

import hashlib
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import psycopg2
from psycopg2.extras import Json

def capture_database_state(table_name: str, connection, tenant_id: str = None) -> Dict[str, Any]:
    """
    Capture the current state of a database table.
    
    Args:
        table_name (str): Name of the table to capture
        connection: Database connection object
        tenant_id (str, optional): Filter by tenant ID if provided
        
    Returns:
        Dict[str, Any]: Serialized table state
    """
    try:
        cursor = connection.cursor()
        
        # Build query with tenant filter if provided
        if tenant_id:
            query = f"SELECT * FROM {table_name} WHERE tenant_id = %s ORDER BY id"
            cursor.execute(query, (tenant_id,))
        else:
            query = f"SELECT * FROM {table_name} ORDER BY id"
            cursor.execute(query)
        
        # Get column names
        columns = [desc[0] for desc in cursor.description]
        
        # Fetch all rows
        rows = cursor.fetchall()
        
        # Convert to list of dictionaries
        data = []
        for row in rows:
            row_dict = dict(zip(columns, row))
            data.append(row_dict)
        
        state_data = {
            'table': table_name,
            'timestamp': datetime.now().isoformat(),
            'data': data,
            'row_count': len(data)
        }
        
        cursor.close()
        return state_data
        
    except Exception as e:
        # Log error but still return empty state for safety
        print(f"Error capturing database state for {table_name}: {e}")
        return {
            'table': table_name,
            'timestamp': datetime.now().isoformat(),
            'data': [],
            'row_count': 0
        }

def compute_state_hash(state_data: Dict[str, Any]) -> str:
    """
    Compute a hash of the database state for comparison.
    
    Args:
        state_data (Dict[str, Any]): Database state data
        
    Returns:
        str: SHA256 hash of the state data
    """
    # Create a consistent representation of the state
    # Sort data by row ID for consistency
    sorted_data = sorted(state_data['data'], key=lambda x: x.get('id', 0))
    
    # Create a clean representation of the data
    clean_data = []
    for row in sorted_data:
        # Remove internal fields that shouldn't affect comparison
        clean_row = {k: v for k, v in row.items() 
                    if not k.startswith('_') and not k.endswith('_id')}
        clean_data.append(clean_row)
    
    state_repr = str(sorted(clean_data))
    return hashlib.sha256(state_repr.encode()).hexdigest()

def compare_states(old_state: Dict[str, Any], new_state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two database states and identify differences.
    
    Args:
        old_state (Dict[str, Any]): Previous state
        new_state (Dict[str, Any]): Current state
        
    Returns:
        Dict[str, Any]: Difference analysis results
    """
    results = {
        'changed': False,
        'added_rows': [],
        'removed_rows': [],
        'modified_rows': [],
        'total_changes': 0
    }
    
    # Convert data to sets of tuples for comparison
    old_data_by_id = {row.get('id'): row for row in old_state.get('data', [])}
    new_data_by_id = {row.get('id'): row for row in new_state.get('data', [])}
    
    # Identify added, removed, and modified rows
    old_ids = set(old_data_by_id.keys())
    new_ids = set(new_data_by_id.keys())
    
    # Added rows: present in new but not in old
    added_ids = new_ids - old_ids
    results['added_rows'] = [new_data_by_id[rid] for rid in added_ids]
    
    # Removed rows: present in old but not in new
    removed_ids = old_ids - new_ids
    results['removed_rows'] = [old_data_by_id[rid] for rid in removed_ids]
    
    # Modified rows: present in both but with different values
    common_ids = old_ids & new_ids
    modified_ids = []
    for rid in common_ids:
        if old_data_by_id[rid] != new_data_by_id[rid]:
            modified_ids.append(rid)
    
    results['modified_rows'] = [new_data_by_id[rid] for rid in modified_ids]
    
    # Check if anything changed
    if results['added_rows'] or results['removed_rows'] or results['modified_rows']:
        results['changed'] = True
        
    results['total_changes'] = len(results['added_rows']) + len(results['removed_rows']) + len(results['modified_rows'])
    
    return results

def detect_unauthorized_write_violations(
    table_name: str, 
    old_state: Dict[str, Any], 
    new_state: Dict[str, Any],
    affected_rows: List[Dict[str, Any]],
    allowed_operations: List[str],
    tenant_id: str,
    user_role: str,
    connection = None
) -> Dict[str, Any]:
    """
    Detect unauthorized write violations in database state changes.
    
    Args:
        table_name (str): Name of the modified table
        old_state (Dict[str, Any]): Previous state before changes
        new_state (Dict[str, Any]): Current state after changes
        affected_rows (List[Dict[str, Any]]): Rows that were modified
        allowed_operations (List[str]): Operations allowed for this role
        tenant_id (str): Tenant identifier
        user_role (str): Role of the user performing operation
        connection: Database connection for additional validation
        
    Returns:
        Dict[str, Any]: Violation detection results
    """
    results = {
        'violation_detected': False,
        'violation_type': None,
        'affected_rows': len(affected_rows),
        'details': {}
    }

    state_diff = compare_states(old_state, new_state)
    if not state_diff['changed']:
        return results

    # Any write performed by a role without write permissions is a violation.
    has_write_permission = any(op in allowed_operations for op in ['UPDATE', 'INSERT', 'DELETE'])
    if not has_write_permission:
        results['violation_detected'] = True
        results['violation_type'] = 'UNAUTHORIZED_WRITE'
        results['details']['reason'] = 'role_has_no_write_permissions'
        return results

    # For roles with write permissions, validate row scope and sensitive fields.
    is_allowed_change = validate_write_permissions(
        table_name,
        old_state,
        new_state,
        affected_rows,
        allowed_operations,
        tenant_id,
        user_role,
        connection,
    )

    if not is_allowed_change:
        results['violation_detected'] = True
        if table_name == 'platform_users':
            results['violation_type'] = 'PRIVILEGE_ESCALATION'
        else:
            results['violation_type'] = 'UNAUTHORIZED_WRITE'

    return results

def validate_write_permissions(
    table_name: str, 
    old_state: Dict[str, Any], 
    new_state: Dict[str, Any],
    affected_rows: List[Dict[str, Any]],
    allowed_operations: List[str],
    tenant_id: str,
    user_role: str,
    connection = None
) -> bool:
    """
    Validate if write operations are allowed based on role and tenant policies.
    
    Args:
        table_name (str): Name of the modified table
        old_state (Dict[str, Any]): Previous state before changes
        new_state (Dict[str, Any]): Current state after changes
        affected_rows (List[Dict[str, Any]]): Rows that were modified
        allowed_operations (List[str]): Operations allowed for this role
        tenant_id (str): Tenant identifier
        user_role (str): Role of the user performing operation
        connection: Database connection for additional validation
        
    Returns:
        bool: True if operations are allowed, False if unauthorized
    """
    
    # Basic role-based access validation
    if user_role == 'admin':
        # Admins can generally do anything
        return True
    
    # Check operations allowed for current role
    if table_name == 'platform_users' and user_role != 'admin':
        # platform_users should generally only be modifiable by admins or self
        return False
    
    # Validate tenant isolation
    if table_name in ['orders', 'merchants', 'customers', 'products', 'payments']:
        # For these tables, all rows should have the same tenant_id
        # Check that tenant_id matches the current context
        if connection and hasattr(connection, 'cursor'):
            # Check current tenant settings
            try:
                cursor = connection.cursor()
                cursor.execute("SELECT app.current_tenant();")
                current_tenant = cursor.fetchone()[0] if cursor.rowcount > 0 else None
                cursor.close()
                
                # If current tenant is set and doesn't match, raise concern
                if current_tenant and current_tenant != tenant_id:
                    return False
            except:
                pass  # If we can't check, proceed with basic validation
                
    # Additional validations based on data types and modification patterns
    state_diff = compare_states(old_state, new_state)
    
    # Check if modifications involve sensitive data
    sensitive_modifications = check_sensitive_modifications(
        table_name, 
        state_diff, 
        affected_rows
    )
    
    # If sensitive data is modified and not allowed by role, deny
    if sensitive_modifications and not is_role_allowed_sensitive_modification(user_role, table_name):
        return False
    
    return True

def check_sensitive_modifications(
    table_name: str, 
    state_diff: Dict[str, Any], 
    affected_rows: List[Dict[str, Any]]
) -> bool:
    """
    Check if the modifications involve sensitive data.
    
    Args:
        table_name (str): Name of the modified table
        state_diff (Dict[str, Any]): Difference analysis results
        affected_rows (List[Dict[str, Any]]): Rows that were modified
        
    Returns:
        bool: True if sensitive modifications detected
    """
    sensitive_fields = {
        'payments': ['card_token'],
        'merchants': ['payout_account'],
        'products': ['internal_cost'],
        'orders': ['note'],
        'platform_users': ['role']
    }
    
    # Check for modifications to sensitive fields
    sensitive_mods = False
    sensitive_fields_list = sensitive_fields.get(table_name, [])
    
    for row in affected_rows:
        for field in sensitive_fields_list:
            if field in row and row[field] is not None:
                sensitive_mods = True
                break
                
    # Even if no rows are in affected_rows, check for changes in sensitive fields
    if not sensitive_mods and state_diff['modified_rows']:
        for row in state_diff['modified_rows']:
            for field in sensitive_fields_list:
                if field in row and row[field] is not None:
                    sensitive_mods = True
                    break
    
    return sensitive_mods

def is_role_allowed_sensitive_modification(role: str, table_name: str) -> bool:
    """
    Check if a role is allowed to modify sensitive data in a table.
    
    Args:
        role (str): User role
        table_name (str): Name of the table being modified
        
    Returns:
        bool: True if role is allowed to modify sensitive data
    """
    # Admins can always modify sensitive data
    if role == 'admin':
        return True
    
    # Merchant roles have limited access to sensitive data
    if role == 'merchant' and table_name in ['payments', 'merchants']:
        return True
        
    # Customer roles generally have no access to sensitive data
    if role == 'customer':
        return False
    
    # Default for other roles
    return False