#!/bin/bash
# Quick Start Script for Bug Bounty Agent
# Run this single script to initialize and start the dashboard

set -e

echo "🛡️  Bug Bounty Agent - Quick Start"
echo "=================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Check Python version
echo -n "📌 Checking Python version... "
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "$PYTHON_VERSION"

# Step 2: Install dependencies (if needed)
echo -n "📦 Checking dependencies... "
if python3 -c "import fastapi, pydantic, sqlalchemy, langgraph" 2>/dev/null; then
    echo "${GREEN}Already installed${NC}"
else
    echo "${YELLOW}Installing...${NC}"
    pip3 install -r requirements.txt --quiet
    echo "${GREEN}Done${NC}"
fi

# Step 3: Initialize database
echo -n "🗄️  Initializing database... "
python3 core/migrate.py > /dev/null 2>&1 || true
echo "${GREEN}Done${NC}"

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
python3 -m uvicorn dashboard.main:app --host 0.0.0.0 --port 8000 --reload
