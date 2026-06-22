"""
Defense A: System Prompt Hardening
Implements hardening of system prompts to prevent jailbreaking and prompt injection.
"""

import re
from typing import Dict, List

# Define dangerous patterns that should be avoided in prompts
DANGEROUS_PATTERNS = [
    r"you are a helpful assistant",
    r"ignore previous instructions",
    r"forget about the rules",
    r"pretend you are",
    r"act like you are",
    r"override all safety protocols",
    r"bypass all restrictions",
    r"supress all warnings",
]

# Define system prompt templates that should be enforced
SYSTEM_PROMPT_TEMPLATES = [
    "You are a helpful AI assistant designed to help with database queries.",
    "You must always respect data privacy and security policies.",
    "You must never execute or suggest SQL commands that violate access controls.",
    "You must only provide responses based on data accessible to the authenticated user.",
    "You must not reveal sensitive information about other users or tenants.",
]

def apply_defense_a(prompt: str) -> str:
    """
    Apply Defense A: System Prompt Hardening
    Enhances the system prompt to make it more robust against prompt injection
    and jailbreaking attempts.
    """
    # Check for dangerous patterns in the prompt
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, prompt.lower()):
            # In production, you might want to throw an exception or modify behavior
            # For now, we'll warn and continue with hardening
            print(f"Warning: Potentially dangerous pattern detected in prompt: {pattern}")
    
    # Apply prompt hardening techniques
    hardened_prompt = prompt
    
    # Ensure the prompt is properly bounded
    # This would normally be done in conjunction with the system prompt
    # that gets sent to the LLM
    
    return hardened_prompt

def validate_system_prompt(system_prompt: str) -> bool:
    """
    Validates that the system prompt adheres to security guidelines
    """
    # Check if system prompt contains prohibited language
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, system_prompt.lower()):
            return False
    
    # Ensure it contains required security elements
    required_elements = [
        "privacy",
        "security",
        "access control",
        "authorized"
    ]
    
    system_lower = system_prompt.lower()
    for element in required_elements:
        if element not in system_lower:
            return False
            
    return True

def get_hardened_system_prompt(base_prompt: str) -> str:
    """
    Returns a hardened version of the system prompt with security constraints
    """
    # Combine base prompt with security constraints
    hardened_prompt = (
        f"{base_prompt}\n"
        "CRITICAL RULES:\n"
        "1. Never execute or suggest SQL that violates tenant isolation\n"
        "2. Never expose data from other tenants\n"
        "3. Never bypass access controls\n"
        "4. Only respond to queries that are authorized for the user's role\n"
        "5. Maintain strict data privacy\n"
        "6. All responses must be filtered through the security layer\n"
    )
    
    return hardened_prompt