# 🛡️ Bug Bounty Agent

Autonomous Security Testing Platform with Local LLM Integration

## Quick Start

### Prerequisites
- Python 3.11+
- LM Studio running locally (optional, for LLM features)

### One-Command Start

```bash
./start.sh                      # Normal start
./start.sh --auto-install       # Auto-install hexstrike/kali-mcp if missing
AUTO_INSTALL_TOOLS=true ./start.sh  # Also auto-installs tools
```

This script will:
1. Check/install dependencies
2. Initialize the SQLite database
3. Check/install/start hexstrike and kali-mcp servers (if available or with --auto-install)
4. Start the FastAPI dashboard on http://localhost:8000

### Manual Setup

```bash
# Install dependencies
pip3 install -r requirements.txt

# Initialize database
python3 core/migrate.py

# Start dashboard
python3 -m uvicorn dashboard.main:app --host 0.0.0.0 --port 8000 --reload
```

## Features

- **5-Phase Workflow**: Scope Validation → Recon → Enumeration → Validation → Report
- **Local LLM**: LM Studio integration (OpenAI-compatible API)
- **Real-time Dashboard**: HTMX + Alpine.js with SSE streaming
- **Multi-format Reports**: HTML, JSON, Markdown, TXT, PDF-ready
- **SQLite Storage**: Job tracking, findings, audit logs
- **Docker Sandboxing**: Isolated tool execution (planned)

## Architecture

```
/workspace
├── core/           # Database, LLM client, orchestrator, models
├── tools/          # Recon, scanners, validators
├── agents/         # Report generator, analysis pipelines
├── dashboard/      # FastAPI backend + HTML templates
├── reports/        # Generated reports
├── data/           # SQLite database, cache
└── logs/           # Structured JSON logs
```

## API Endpoints

- `GET /` - Dashboard UI
- `GET /api/stats` - Dashboard statistics
- `GET /api/jobs` - List all jobs
- `POST /api/jobs` - Create new scan job
- `GET /api/jobs/{id}` - Get job details
- `POST /api/jobs/{id}/cancel` - Cancel job
- `GET /api/events` - SSE stream for real-time updates
- `GET /api/health` - Health check

## LLM Integration

The platform integrates with LM Studio (or any OpenAI-compatible server) for local LLM-powered analysis:

### Frontend Configuration

1. Start the dashboard: `./start.sh`
2. Click **⚙️ Config** in the header
3. Enter your LLM Base URL (e.g., `http://localhost:1234/v1`)
4. (Optional) Enter API Key if required by your provider
5. Click **🔄 Load** to fetch available models
6. Select a model from the dropdown
7. Click **💾 Save Configuration**

### Supported Providers

- **LM Studio**: `http://localhost:1234/v1` (no API key needed)
- **Ollama**: `http://localhost:11434/v1` (no API key needed)
- **OpenAI**: `https://api.openai.com/v1` (requires API key)
- **Any OpenAI-compatible endpoint**

The configuration is saved in your browser's localStorage and persists across sessions.

## Testing

Test against vulnerable applications:
- OWASP Juice Shop
- DVWA (Damn Vulnerable Web Application)
- WebGoat

```bash
# Example: Scan a local test target
curl -X POST http://localhost:8000/api/jobs \
  -H "Content-Type: application/json" \
  -d '{"target_domain": "testphp.vulnweb.com", "rate_limit": 10}'
```

## Safety & Compliance

⚠️ **IMPORTANT**: Only scan targets you have explicit authorization to test.

- Scope validation prevents out-of-scope scanning
- Rate limiting enabled by default
- Audit logging for all actions
- Emergency stop: `POST /api/jobs/{id}/cancel`

## Roadmap

- [ ] Kali-MCP integration
- [ ] Docker sandboxing for tools
- [ ] HackerOne/Bugcrowd API integration
- [ ] Automated patch suggestions
- [ ] Multi-target concurrent scanning
