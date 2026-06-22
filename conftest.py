"""
Pytest configuration for gateway tests
"""

import sys
import os

# Add gateway directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'gateway'))