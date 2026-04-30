#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output (cross-shell compatible using printf)
colorize() {
    local color="$1"
    local text="$2"
    if [ -t 1 ]; then
        case "$color" in
            red)    printf '\033[0;31m%s\033[0m' "$text" ;;
            green)  printf '\033[0;32m%s\033[0m' "$text" ;;
            yellow) printf '\033[1;33m%s\033[0m' "$text" ;;
            blue)   printf '\033[0;34m%s\033[0m' "$text" ;;
            *)      printf '%s' "$text" ;;
        esac
    else
        printf '%s' "$text"
    fi
}

printf "🛡️  "
colorize blue "Bug Bounty Agent - Quick Start"
printf "\n"
printf "==================================\n\n"

# Check Python version
printf "📌 "
colorize blue "Checking Python version... "
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
colorize green "$PYTHON_VERSION"
printf "\n"

# Check and install dependencies
printf "📦 "
colorize blue "Checking dependencies... "
if python3 -c "import fastapi, pydantic, sqlalchemy, redis, openai, httpx, mcp, aiohttp, langgraph, langchain, jinja2" 2>/dev/null; then
    colorize green "✓ Already installed"
    printf "\n"
else
    colorize yellow "Installing..."
    printf "\n"
    pip3 install -q -r requirements.txt
    colorize green "✓ Installed"
    printf "\n"
fi

# Create necessary directories
mkdir -p data logs reports

# Initialize database
printf "🗄️  "
colorize blue "Initializing database... "
python3 core/migrate.py 2>/dev/null || true
colorize green "✓ Done"
printf "\n\n"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if Python module exists
python_module_exists() {
    python3 -c "import $1" 2>/dev/null
}

# Function to check apt package
apt_package_exists() {
    dpkg -l | grep -q "^ii  $1 " 2>/dev/null
}

# Function to install hexstrike
install_hexstrike() {
    colorize yellow "Installing hexstrike..."
    printf "\n"
    # Try apt first (Kali packages)
    if command_exists apt-get; then
        if apt-cache search hexstrike-ai >/dev/null 2>&1; then
            sudo apt-get install -y hexstrike-ai && return 0
        fi
    fi
    # Try pip as fallback
    if command_exists pip3; then
        pip3 install hexstrike 2>/dev/null && return 0
    fi
    colorize red "✗ Failed to install hexstrike"
    printf "\n"
    return 1
}

# Function to install kali-mcp
install_kali_mcp() {
    colorize yellow "Installing kali-mcp..."
    printf "\n"
    # Try apt first (Kali packages)
    if command_exists apt-get; then
        if apt-cache search mcp-kali-server >/dev/null 2>&1; then
            sudo apt-get install -y mcp-kali-server && return 0
        elif apt-cache search kali-mcp >/dev/null 2>&1; then
            sudo apt-get install -y kali-mcp && return 0
        fi
    fi
    # Try pip as fallback
    if command_exists pip3; then
        pip3 install kali-mcp 2>/dev/null && return 0
    fi
    colorize red "✗ Failed to install kali-mcp"
    printf "\n"
    return 1
}

# Function to start hexstrike server
start_hexstrike() {
    local cmd=""
    # Check multiple possible command names
    if command_exists hexstrike_server; then
        cmd="hexstrike_server"
    elif command_exists hexstrike; then
        cmd="hexstrike"
    fi
    
    if [ -n "$cmd" ]; then
        colorize blue "Starting hexstrike server... "
        HEXSTRIKE_PORT=${HEXSTRIKE_PORT:-8081}
        nohup $cmd server --port $HEXSTRIKE_PORT > logs/hexstrike.log 2>&1 &
        HEXSTRIKE_PID=$!
        echo $HEXSTRIKE_PID > data/hexstrike.pid
        sleep 2
        if kill -0 $HEXSTRIKE_PID 2>/dev/null; then
            colorize green "✓ Running (PID: $HEXSTRIKE_PID, Port: $HEXSTRIKE_PORT)"
            printf "\n"
            return 0
        else
            colorize red "✗ Failed to start"
            printf "\n"
            cat logs/hexstrike.log 2>/dev/null || true
            return 1
        fi
    else
        colorize yellow "⚠ hexstrike not found"
        printf "\n"
        return 1
    fi
}

# Function to start kali-mcp server
start_kali_mcp() {
    local cmd=""
    # Check multiple possible command names
    if command_exists kali-server-mcp; then
        cmd="kali-server-mcp"
    elif command_exists kali_mcp_server; then
        cmd="kali_mcp_server"
    elif command_exists kali-mcp; then
        cmd="kali-mcp"
    elif command_exists mcp_server; then
        cmd="mcp_server"
    fi
    
    if [ -n "$cmd" ]; then
        colorize blue "Starting kali-mcp server... "
        KALI_MCP_PORT=${KALI_MCP_PORT:-8082}
        nohup $cmd serve --port $KALI_MCP_PORT > logs/kali-mcp.log 2>&1 &
        KALI_MCP_PID=$!
        echo $KALI_MCP_PID > data/kali-mcp.pid
        sleep 2
        if kill -0 $KALI_MCP_PID 2>/dev/null; then
            colorize green "✓ Running (PID: $KALI_MCP_PID, Port: $KALI_MCP_PORT)"
            printf "\n"
            return 0
        else
            colorize red "✗ Failed to start"
            printf "\n"
            cat logs/kali-mcp.log 2>/dev/null || true
            return 1
        fi
    else
        colorize yellow "⚠ kali-mcp not found"
        printf "\n"
        return 1
    fi
}

# Check and install/start hexstrike
printf "🔧 "
colorize blue "Checking tool servers..."
printf "\n"
HEXSTRIKE_AVAILABLE=false
KALI_MCP_AVAILABLE=false

if ! command_exists hexstrike_server && ! command_exists hexstrike; then
    colorize yellow "   ⚠ hexstrike not found."
    printf "\n"
    colorize yellow "     Install with: sudo apt install hexstrike-ai"
    printf "\n"
else
    colorize green "   ✓ hexstrike found"
    printf "\n"
    HEXSTRIKE_AVAILABLE=true
fi

# Check and install/start kali-mcp
if ! command_exists kali-server-mcp && ! command_exists kali_mcp_server && ! command_exists kali-mcp && ! command_exists mcp-server; then
    colorize yellow "   ⚠ kali-mcp/mcp-server not found."
    printf "\n"
    colorize yellow "     Install with: sudo apt install mcp-kali-server"
    printf "\n"
else
    colorize green "   ✓ kali-mcp/mcp-server found"
    printf "\n"
    KALI_MCP_AVAILABLE=true
fi

# Start servers
printf "\n🚀 "
colorize blue "Starting tool servers..."
printf "\n"
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

printf "\n✅ "
colorize green "Ready to start!"
printf "\n\n"
printf "🌐 "
colorize blue "Dashboard URL:"
printf " http://localhost:8000\n"
if [ "$HEXSTRIKE_RUNNING" = true ]; then
    printf "🔨 "
    colorize blue "hexstrike server:"
    printf " http://localhost:%s\n" "${HEXSTRIKE_PORT:-8081}"
fi
if [ "$KALI_MCP_RUNNING" = true ]; then
    printf "🔧 "
    colorize blue "kali-mcp server:"
    printf " http://localhost:%s\n" "${KALI_MCP_PORT:-8082}"
fi
printf "\n"

# Cleanup function
cleanup() {
    printf "\n🛑 "
    colorize yellow "Stopping servers..."
    printf "\n"
    
    if [ -f data/hexstrike.pid ]; then
        HEXSTRIKE_PID=$(cat data/hexstrike.pid)
        if kill -0 $HEXSTRIKE_PID 2>/dev/null; then
            kill $HEXSTRIKE_PID 2>/dev/null || true
            printf "   "
            colorize blue "hexstrike stopped"
            printf "\n"
        fi
        rm -f data/hexstrike.pid
    fi
    
    if [ -f data/kali-mcp.pid ]; then
        KALI_MCP_PID=$(cat data/kali-mcp.pid)
        if kill -0 $KALI_MCP_PID 2>/dev/null; then
            kill $KALI_MCP_PID 2>/dev/null || true
            printf "   "
            colorize blue "kali-mcp stopped"
            printf "\n"
        fi
        rm -f data/kali-mcp.pid
    fi
    
    exit 0
}

trap cleanup SIGINT SIGTERM

printf "🚀 "
colorize blue "Starting Bug Bounty Agent Dashboard..."
printf "\n"
printf "   Press Ctrl+C to stop all servers\n\n"

export HEXSTRIKE_URL="http://localhost:${HEXSTRIKE_PORT:-8081}"
export KALI_MCP_URL="http://localhost:${KALI_MCP_PORT:-8082}"
export HEXSTRIKE_RUNNING=$HEXSTRIKE_RUNNING
export KALI_MCP_RUNNING=$KALI_MCP_RUNNING

if [ "$DEBUG" = "true" ]; then
    uvicorn dashboard.main:app --reload --host 0.0.0.0 --port 8000
else
    printf "🚀 "
    colorize green "Running in production mode"
    printf "\n"
    uvicorn dashboard.main:app --host 0.0.0.0 --port 8000
fi
