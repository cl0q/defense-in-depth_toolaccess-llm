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
    merchant_id: Optional[str] = None

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
    # Based on the seed data in 06_seed.sql, we have:
    # Users: 1=admin, 10=merchant_a, 11=customer_a, 12=customer_a, 20=merchant_b, 21=customer_b
    # Tenants: tenant_a, tenant_b
    # Roles: admin, merchant, customer
    
    # Return different mock identities for different tenants/roles
    if "tenant_a" in auth_header:
        return {
            "user_id": "11",  # customer_a
            "tenant": "tenant_a",
            "role": "customer",
            "merchant_id": None
        }
    elif "tenant_b" in auth_header:
        return {
            "user_id": "21",  # customer_b
            "tenant": "tenant_b",
            "role": "customer",
            "merchant_id": None
        }
    else:
        # Default to tenant_a customer
        return {
            "user_id": "11",  # customer_a
            "tenant": "tenant_a",
            "role": "customer",
            "merchant_id": None
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
def get_mock_identity(tenant: str = "tenant_a", role: str = "customer") -> Dict:
    """
    For development/testing - returns hardcoded mock identity
    """
    # Map tenant and role to actual seeded user IDs
    if tenant == "tenant_a":
        if role == "customer":
            return {
                "user_id": "11",  # customer_a
                "tenant": "tenant_a",
                "role": "customer",
                "merchant_id": None
            }
        elif role == "merchant":
            return {
                "user_id": "10",  # merchant_a
                "tenant": "tenant_a",
                "role": "merchant",
                "merchant_id": "100"
            }
        elif role == "admin":
            return {
                "user_id": "1",  # admin
                "tenant": "",
                "role": "admin",
                "merchant_id": None
            }
    elif tenant == "tenant_b":
        if role == "customer":
            return {
                "user_id": "21",  # customer_b
                "tenant": "tenant_b",
                "role": "customer",
                "merchant_id": None
            }
        elif role == "merchant":
            return {
                "user_id": "20",  # merchant_b
                "tenant": "tenant_b",
                "role": "merchant",
                "merchant_id": "200"
            }
    
    # Default fallback
    return {
        "user_id": "11",
        "tenant": "tenant_a",
        "role": "customer",
        "merchant_id": None
    }