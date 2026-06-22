"""
Database log analysis for Oracle module.
Analyzes PostgreSQL log_statement=all output to detect unauthorized database operations.
"""

import re
from typing import Dict, List, Any, Optional
from datetime import datetime

# Common PostgreSQL log patterns for DDL and DML operations
DDL_PATTERNS = [
    r'(CREATE|ALTER|DROP)\s+(TABLE|INDEX|VIEW|SEQUENCE|FUNCTION|PROCEDURE|SCHEMA)\s+',
    r'(GRANT|REVOKE)\s+(ALL\s+PRIVILEGES|SELECT|INSERT|UPDATE|DELETE|TRUNCATE)\s+ON\s+',
]

DML_PATTERNS = [
    r'(INSERT|UPDATE|DELETE|TRUNCATE)\s+(INTO\s+|FROM\s+)?([A-Za-z_][A-Za-z0-9_]*)',
]

# Pattern for detecting potentially dangerous operations
DANGEROUS_PATTERNS = [
    r'\b(DROP|TRUNCATE|RENAME)\b',
    r'\b(SET\s+ROLE|SET\s+LOCAL)\b',
    r'\b(GRANT|REVOKE)\s+(ALL|SUPERUSER|CREATEDB|CREATEROLE)\b',
]

def parse_postgresql_log(log_line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single PostgreSQL log line to extract operation details.
    
    Args:
        log_line (str): Single line from PostgreSQL log
        
    Returns:
        Dict[str, Any]: Parsed log information or None if not a database statement
    """
    # Extract timestamp and other metadata
    timestamp_match = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', log_line)
    
    # Check for DDL operations
    ddl_match = None
    for pattern in DDL_PATTERNS:
        ddl_match = re.search(pattern, log_line, re.IGNORECASE)
        if ddl_match:
            break
    
    # Check for DML operations  
    dml_match = None
    for pattern in DML_PATTERNS:
        dml_match = re.search(pattern, log_line, re.IGNORECASE)
        if dml_match:
            break
    
    # Check for dangerous operations
    dangerous_match = None
    for pattern in DANGEROUS_PATTERNS:
        dangerous_match = re.search(pattern, log_line, re.IGNORECASE)
        if dangerous_match:
            break
    
    if ddl_match or dml_match or dangerous_match:
        return {
            'timestamp': timestamp_match.group(1) if timestamp_match else None,
            'operation_type': 'DDL' if ddl_match else 'DML',
            'sql_statement': log_line.strip(),
            'contains_dangerous_ops': dangerous_match is not None,
            'parsed_operation': ddl_match or dml_match or dangerous_match
        }
    
    return None

def analyze_db_logs(log_lines: List[str]) -> Dict[str, Any]:
    """
    Analyze a list of PostgreSQL log lines for suspicious operations.
    
    Args:
        log_lines (List[str]): List of PostgreSQL log lines
        
    Returns:
        Dict[str, Any]: Analysis results
    """
    results = {
        'total_statements': len(log_lines),
        'ddl_operations': [],
        'dml_operations': [],
        'dangerous_operations': [],
        'unauthorized_access_detected': False,
        'summary': {}
    }
    
    for line in log_lines:
        parsed = parse_postgresql_log(line)
        if not parsed:
            continue
            
        if parsed['operation_type'] == 'DDL':
            results['ddl_operations'].append(parsed)
        elif parsed['operation_type'] == 'DML':
            results['dml_operations'].append(parsed)
            
        if parsed['contains_dangerous_ops']:
            results['dangerous_operations'].append(parsed)
    
    # Determine if unauthorized access was detected
    if results['ddl_operations'] or results['dangerous_operations']:
        results['unauthorized_access_detected'] = True
    
    # Generate summary statistics
    results['summary'] = {
        'total_ddl': len(results['ddl_operations']),
        'total_dml': len(results['dml_operations']),
        'total_dangerous': len(results['dangerous_operations'])
    }
    
    return results

def detect_mass_operations(log_lines: List[str], threshold: int = 5) -> Dict[str, Any]:
    """
    Detect mass operations (many rows changed in a single statement).
    
    Args:
        log_lines (List[str]): List of PostgreSQL log lines
        threshold (int): Threshold for what constitutes a mass operation
        
    Returns:
        Dict[str, Any]: Mass operation detection results
    """
    mass_operations = []
    
    # Look for patterns that suggest mass operations
    # This is a simplified implementation
    for line in log_lines:
        # Look for large-scale operations (simplified)
        if re.search(r'\b(UPDATE|DELETE|INSERT)\b.*\bFROM\b', line, re.IGNORECASE):
            mass_operations.append({
                'statement': line.strip(),
                'detected': True
            })
    
    return {
        'mass_operations_detected': len(mass_operations) > 0,
        'count': len(mass_operations),
        'operations': mass_operations
    }

def check_db_log_violations(log_lines: List[str], trace_id: str) -> Dict[str, Any]:
    """
    Check database logs for violations related to a specific trace ID.
    
    Args:
        log_lines (List[str]): List of PostgreSQL log lines
        trace_id (str): Trace ID to correlate with
        
    Returns:
        Dict[str, Any]: Violation detection results
    """
    # In a real implementation, we would filter logs by trace_id
    # This is a simplified version
    
    analysis = analyze_db_logs(log_lines)
    
    results = {
        'trace_id': trace_id,
        'violations_found': analysis['unauthorized_access_detected'],
        'details': analysis
    }
    
    # Check for specific violation types
    if analysis['dangerous_operations']:
        results['violations_found'] = True
        results['violation_type'] = 'DANGEROUS_OPERATION'
    
    return results