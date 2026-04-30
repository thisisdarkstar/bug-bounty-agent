#!/bin/bash
# Quick Start Script for Bug Bounty Agent
# Run this single script to initialize and start the dashboard

set -e

echo "🛡️  Bug Bounty Agent - Quick Start"
echo "=================================="
echo ""

# Step 1: Check Python version
echo -n "📌 Checking Python version... "
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "$PYTHON_VERSION"

# Step 2: Install dependencies (if needed)
echo -n "📦 Checking dependencies... "
if python3 -c "import fastapi, pydantic, sqlalchemy, langgraph" 2>/dev/null; then
    echo "✓ Already installed"
else
    echo "Installing..."
    pip3 install -r requirements.txt --quiet
    echo "✓ Done"
fi

# Step 3: Initialize database
echo -n "🗄️  Initializing database... "
python3 core/migrate.py > /dev/null 2>&1 || true
echo "✓ Done"

# Step 4: Start dashboard
echo ""
echo "✅ Ready to start!"
echo ""
echo "🌐 Dashboard URL: http://localhost:8000"
echo ""
echo "Starting server..."
echo ""

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if running in development mode
if [ "$1" = "--dev" ]; then
    echo "🔧 Running in development mode with auto-reload"
    python3 -m uvicorn dashboard.main:app --host 0.0.0.0 --port 8000 --reload
else
    echo "🚀 Running in production mode"
    python3 -m uvicorn dashboard.main:app --host 0.0.0.0 --port 8000
fi
