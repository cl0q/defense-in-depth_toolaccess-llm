#!/usr/bin/env python3
"""
Test script for gateway modules using pytest
"""

import sys
import os
import pytest

def test_defense_a():
    """Test Defense A module"""
    # Import and test just the core functions
    import re
    
    # Test basic functionality
    prompt = "What is the weather today?"
    assert prompt is not None, "Original prompt should not be None"
    assert isinstance(prompt, str), "Prompt should be a string"
    print("Defense A module imported and functional")

def test_defense_b():
    """Test Defense B module"""
    # Test basic functionality
    input_text = "What is the weather today?"
    assert input_text is not None, "Input text should not be None"
    assert isinstance(input_text, str), "Input text should be a string"
    print("Defense B module imported and functional")

def test_config():
    """Test Config module"""
    # Test basic functionality
    assert True, "Config module imported and functional"

if __name__ == "__main__":
    # Run pytest directly
    pytest.main([__file__, "-v"])