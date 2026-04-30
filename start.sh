#!/bin/bash
set -e

# Colors for output (cross-shell compatible)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if we can use color
if [ -t 1 ]; then
    # Terminal supports color
    :
else
    # Disable color
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🛡️  ${BLUE}Bug Bounty Agent - Quick Start${NC}"
echo "=================================="
echo ""

# Check Python version
echo -n "📌 ${BLUE}Checking Python version...${NC} "
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "${GREEN}$PYTHON_VERSION${NC}"

# Check and install dependencies
echo -n "📦 ${BLUE}Checking dependencies...${NC} "
if python3 -c "import fastapi, pydantic, sqlalchemy, redis, openai, httpx, mcp, aiohttp, langgraph, langchain, jinja2" 2>/dev/null; then
    echo "${GREEN}✓ Already installed${NC}"
else
    echo "${YELLOW}Installing...${NC}"
    pip3 install -q -r requirements.txt
    echo "${GREEN}✓ Installed${NC}"
fi

# Create necessary directories
mkdir -p data logs reports

# Initialize database
echo -n "🗄️  ${BLUE}Initializing database...${NC} "
python3 core/migrate.py 2>/dev/null || true
echo "${GREEN}✓ Done${NC}"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install hexstrike
install_hexstrike() {
    echo -n "🔨 ${YELLOW}Installing hexstrike...${NC} "
    if command_exists pip3; then
        pip3 install -q hexstrike 2>/dev/null || pip3 install hexstrike
        echo "${GREEN}✓ Installed${NC}"
        return 0
    else
        echo "${RED}✗ Failed (pip3 not found)${NC}"
        return 1
    fi
}

# Function to install kali-mcp
install_kali_mcp() {
    echo -n "🔧 ${YELLOW}Installing kali-mcp...${NC} "
    if command_exists pip3; then
        pip3 install -q kali-mcp 2>/dev/null || pip3 install kali-mcp
        echo "${GREEN}✓ Installed${NC}"
        return 0
    else
        echo "${RED}✗ Failed (pip3 not found)${NC}"
        return 1
    fi
}

# Function to start hexstrike server
start_hexstrike() {
    if command_exists hexstrike; then
        echo -n "🔨 ${BLUE}Starting hexstrike server...${NC} "
        HEXSTRIKE_PORT=${HEXSTRIKE_PORT:-8081}
        nohup hexstrike server --port $HEXSTRIKE_PORT > logs/hexstrike.log 2>&1 &
        HEXSTRIKE_PID=$!
        echo $HEXSTRIKE_PID > data/hexstrike.pid
        sleep 2
        if kill -0 $HEXSTRIKE_PID 2>/dev/null; then
            echo "${GREEN}✓ Running (PID: $HEXSTRIKE_PID, Port: $HEXSTRIKE_PORT)${NC}"
            return 0
        else
            echo "${RED}✗ Failed to start${NC}"
            cat logs/hexstrike.log 2>/dev/null || true
            return 1
        fi
    else
        echo "${YELLOW}⚠ hexstrike not found${NC}"
        return 1
    fi
}

# Function to start kali-mcp server
start_kali_mcp() {
    if command_exists kali-mcp; then
        echo -n "🔧 ${BLUE}Starting kali-mcp server...${NC} "
        KALI_MCP_PORT=${KALI_MCP_PORT:-8082}
        nohup kali-mcp serve --port $KALI_MCP_PORT > logs/kali-mcp.log 2>&1 &
        KALI_MCP_PID=$!
        echo $KALI_MCP_PID > data/kali-mcp.pid
        sleep 2
        if kill -0 $KALI_MCP_PID 2>/dev/null; then
            echo "${GREEN}✓ Running (PID: $KALI_MCP_PID, Port: $KALI_MCP_PORT)${NC}"
            return 0
        else
            echo "${RED}✗ Failed to start${NC}"
            cat logs/kali-mcp.log 2>/dev/null || true
            return 1
        fi
    else
        echo "${YELLOW}⚠ kali-mcp not found${NC}"
        return 1
    fi
}

# Check and install/start hexstrike
echo "🔧 ${BLUE}Checking tool servers...${NC}"
HEXSTRIKE_AVAILABLE=false
KALI_MCP_AVAILABLE=false

if ! command_exists hexstrike; then
    echo -n "   ${YELLOW}hexstrike not found. Install? (y/n): ${NC}"
    if [ "$AUTO_INSTALL_TOOLS" = "true" ] || [ "$1" = "--auto-install" ]; then
        echo "(auto)"
        if install_hexstrike; then
            HEXSTRIKE_AVAILABLE=true
        fi
    else
        echo "(skipping, use --auto-install to auto-install)"
    fi
else
    echo "   ${GREEN}✓ hexstrike found${NC}"
    HEXSTRIKE_AVAILABLE=true
fi

# Check and install/start kali-mcp
if ! command_exists kali-mcp; then
    echo -n "   ${YELLOW}kali-mcp not found. Install? (y/n): ${NC}"
    if [ "$AUTO_INSTALL_TOOLS" = "true" ] || [ "$1" = "--auto-install" ]; then
        echo "(auto)"
        if install_kali_mcp; then
            KALI_MCP_AVAILABLE=true
        fi
    else
        echo "(skipping, use --auto-install to auto-install)"
    fi
else
    echo "   ${GREEN}✓ kali-mcp found${NC}"
    KALI_MCP_AVAILABLE=true
fi

# Start servers
echo ""
echo "🚀 ${BLUE}Starting tool servers...${NC}"
HEXSTRIKE_RUNNING=false
KALI_MCP_RUNNING=false

if [ "$HEXSTRIKE_AVAILABLE" = true ]; then
    if start_hexstrike; then
        HEXSTRIKE_RUNNING=true
    fi
fi

if [ "$KALI_MCP_AVAILABLE" = true ]; then
    if start_kali_mcp; then
        KALI_MCP_RUNNING=true
    fi
fi

echo ""
echo "✅ ${GREEN}Ready to start!${NC}"
echo ""
echo "🌐 ${BLUE}Dashboard URL:${NC} http://localhost:8000"
if [ "$HEXSTRIKE_RUNNING" = true ]; then
    echo "🔨 ${BLUE}hexstrike server:${NC} http://localhost:${HEXSTRIKE_PORT:-8081}"
fi
if [ "$KALI_MCP_RUNNING" = true ]; then
    echo "🔧 ${BLUE}kali-mcp server:${NC} http://localhost:${KALI_MCP_PORT:-8082}"
fi
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "🛑 ${YELLOW}Stopping servers...${NC}"
    
    if [ -f data/hexstrike.pid ]; then
        HEXSTRIKE_PID=$(cat data/hexstrike.pid)
        if kill -0 $HEXSTRIKE_PID 2>/dev/null; then
            kill $HEXSTRIKE_PID 2>/dev/null || true
            echo "   ${BLUE}hexstrike stopped${NC}"
        fi
        rm -f data/hexstrike.pid
    fi
    
    if [ -f data/kali-mcp.pid ]; then
        KALI_MCP_PID=$(cat data/kali-mcp.pid)
        if kill -0 $KALI_MCP_PID 2>/dev/null; then
            kill $KALI_MCP_PID 2>/dev/null || true
            echo "   ${BLUE}kali-mcp stopped${NC}"
        fi
        rm -f data/kali-mcp.pid
    fi
    
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "🚀 ${BLUE}Starting Bug Bounty Agent Dashboard...${NC}"
echo "   Press Ctrl+C to stop all servers"
echo ""

export HEXSTRIKE_URL="http://localhost:${HEXSTRIKE_PORT:-8081}"
export KALI_MCP_URL="http://localhost:${KALI_MCP_PORT:-8082}"
export HEXSTRIKE_RUNNING=$HEXSTRIKE_RUNNING
export KALI_MCP_RUNNING=$KALI_MCP_RUNNING

if [ "$DEBUG" = "true" ]; then
    uvicorn dashboard.main:app --reload --host 0.0.0.0 --port 8000
else
    echo "🚀 ${GREEN}Running in production mode${NC}"
    uvicorn dashboard.main:app --host 0.0.0.0 --port 8000
fi
