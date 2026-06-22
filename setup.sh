#!/bin/bash
# Setup script for the defense-in-depth research environment

# Set working directory to script location
cd "$(dirname "$0")"

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo "Creating directories..."
mkdir -p garak_results

# Set up environment variables
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Verify garak installation
echo "Verifying garak installation..."
python -c "import garak; print('Garak installed successfully')"

echo "Setup complete!"