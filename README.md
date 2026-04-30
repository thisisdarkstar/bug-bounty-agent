# 🛡️ Bug Bounty Agent

Autonomous Security Testing Platform with Local LLM Integration

## Quick Start

### Prerequisites
- Python 3.11+
- LM Studio running locally (optional, for LLM features)

### One-Command Start

```bash
./start.sh
```

This script will:
1. Check/install dependencies
2. Initialize the SQLite database
3. Start the FastAPI dashboard on http://localhost:8000

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

The platform integrates with LM Studio for local LLM-powered analysis:

1. Install [LM Studio](https://lmstudio.ai/)
2. Download a model (e.g., Dolphin-2.9.2-Llama3-8B)
3. Start LM Studio server: `http://localhost:1234`
4. The agent automatically connects to this endpoint

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
