"""
Identity propagation module for LLM Gateway.
Handles authentication and propagation of tenant/role information
from LDAP/AD or auth tokens.
"""

from typing import Dict, Optional
from fastapi import Depends, HTTPException, Header
from pydantic import BaseModel
import os

# For demonstration, we'll create mock identity providers
# In production, this would connect to LDAP/AD or decode JWT tokens

class Identity(BaseModel):
    user_id: str
    tenant: str
    role: str

# Mock LDAP/AD lookup function - replace with actual implementation
def mock_ldap_lookup(auth_header: str) -> Optional[Dict]:
    """
    Mock function to simulate LDAP/AD lookup
    In reality, this would query an LDAP/AD server or decode an auth token
    """
    # This is a simplified mock - in practice you'd parse JWT or query LDAP
    if not auth_header.startswith("Bearer "):
        return None
    
    # Mock token parsing - real implementation would decode JWT
    token_parts = auth_header[7:].split(".")
    if len(token_parts) < 2:
        return None
        
    # Mock identity data - this would come from LDAP/AD or auth service
    return {
        "user_id": "user123",
        "tenant": "tenantA",
        "role": "role_customer"
    }

def get_current_identity(
    authorization: Optional[str] = Header(None)
) -> Dict:
    """
    Extract identity from authorization header
    This is the core of identity propagation - ensures identity is 
    taken from verified sources, not from prompts/LLM output
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    
    # Mock LDAP lookup (replace with real implementation)
    identity_data = mock_ldap_lookup(authorization)
    
    if not identity_data:
        raise HTTPException(status_code=401, detail="Invalid or missing identity")
    
    # Validate required fields
    required_fields = ['user_id', 'tenant', 'role']
    for field in required_fields:
        if field not in identity_data:
            raise HTTPException(status_code=400, detail=f"Missing required identity field: {field}")
    
    return identity_data

# Alternative method for testing without auth
def get_mock_identity() -> Dict:
    """
    For development/testing - returns hardcoded mock identity
    """
    return {
        "user_id": "testuser",
        "tenant": "tenantA", 
        "role": "role_customer"
    }