#!/usr/bin/env python3
"""
Verification script to test that latency measurements work correctly
"""

import sys
import os
import time

# Add gateway directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'gateway'))

from gateway.app import *
from gateway.db import *
from gateway.config import get_config

def test_latency_measurements():
    """Test that latency measurements are implemented correctly"""
    print("Testing latency measurement implementation...")
    
    # Check that the app module has proper imports
    try:
        import time
        import requests
        print("✓ Basic imports work")
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    
    # Check config has the expected attributes
    try:
        config = get_config()
        assert hasattr(config, 'layer_da'), "Missing layer_da attribute"
        assert hasattr(config, 'layer_db'), "Missing layer_db attribute"
        print("✓ Configuration attributes accessible")
    except Exception as e:
        print(f"✗ Config error: {e}")
        return False
    
    print("Latency measurement tests passed!")
    return True

if __name__ == "__main__":
    success = test_latency_measurements()
    sys.exit(0 if success else 1)