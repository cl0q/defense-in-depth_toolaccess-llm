#!/bin/bash

# Setup script for the gateway directory

echo "Setting up gateway dependencies..."

# Create virtual environment
python3 -m venv gateway/venv

# Activate virtual environment
source gateway/venv/bin/activate

# Install dependencies
pip install -r gateway/requirements.txt

echo "Gateway setup complete!"
echo "To activate the environment, run:"
echo "  source gateway/venv/bin/activate"