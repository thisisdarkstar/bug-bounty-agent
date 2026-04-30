# Bug Bounty Agent - Autonomous Security Testing Platform

## Overview
A comprehensive autonomous bug bounty hunting agent with local LLM integration, tool orchestration, and real-time dashboard.

## Architecture

### Core Stack
- **Backend**: Python 3.11+ with FastAPI
- **Database**: SQLite (state & findings)
- **Queue**: Redis + Celery (task queue)
- **Isolation**: Docker containers with security hardening
- **LLM**: LM Studio (local, OpenAI-compatible API)

### Directory Structure
```
/workspace
├── core/           # Orchestrator, state machine, LangGraph pipelines
├── tools/          # hexstrike/kali-mcp wrappers, tool integrations
├── agents/         # LLM pipelines, prompt engineering, analysis
├── dashboard/      # Frontend (HTMX + Alpine.js + TailwindCSS)
├── reports/        # Exported reports (HTML, JSON, PDF, Markdown)
├── logs/           # Structured JSON audit logs
├── tests/          # pytest suites, VCR cassettes
├── prompts/        # Versioned prompt library
└── config/         # YAML/JSON configurations
```

### Execution Flow
1. **Scope Validation** → Validate targets against allowlist
2. **Recon** → Passive reconnaissance (subdomain enum, tech detection)
3. **Enumeration** → Active scanning (ports, services, endpoints)
4. **Validation** → Vulnerability verification with PoC generation
5. **Report Generation** → Multi-format export with remediation steps

## Features

### Local LLM Integration (LM Studio)
- Endpoint: `http://localhost:1234/v1`
- Models: 8B-13B instruct models (Dolphin, Mistral, security-fine-tuned)
- Quantization: Q4_K_M / Q5_K_M for 8-12GB VRAM
- Concurrency: asyncio.Semaphore(2), 30s timeout, exponential backoff

### Tool Integration
- **kali-mcp**: MCP SDK integration for Kali tools
- **hexstrike**: Subprocess/aiohttp bridge with structured output
- **Sandboxing**: Docker with seccomp, AppArmor, read-only FS

### Analysis Pipeline
- Hybrid parsing: Regex + LLM semantic analysis + cross-validation
- Finding classification: CWE mapping, CVSS v4.0 scoring
- False positive reduction: SHA-256 deduplication, FP database

### Report Generation
- Templates: Jinja2 with modular sections
- Formats: HTML, TXT, JSON, Markdown, PDF
- Automation: Triggered on job completion

### Web Dashboard
- Real-time log streaming via SSE
- Scan queue monitoring with start/stop/pause
- Finding triage with severity filters and approval gates
- Multi-format report export

## Security & Compliance
- Command sanitization with destructive pattern blocking
- Rate limiting per target and tool
- Dry-run mode for validation
- Immutable audit logs
- Emergency kill endpoint

## Quick Start

### Prerequisites
```bash
# Install LM Studio and download a model
# Start LM Studio server: lmstudio --server

# Install dependencies
pip install -r requirements.txt

# Start Redis
redis-server

# Run migrations
python core/migrate.py
```

### Launch Components
```bash
# Start the orchestrator
python core/orchestrator.py

# Start the dashboard
python dashboard/app.py

# Or use Docker Compose
docker-compose up -d
```

### Access Dashboard
- URL: `http://localhost:8000`
- Default auth: HTTP Basic (configure in `config/auth.yaml`)

## Configuration

### Scope Configuration (`config/scope.yaml`)
```yaml
allowed_targets:
  - domain: example.com
    subdomains: ["*"]
    ports: [80, 443, 8080]
    rate_limit: 10  # requests/second
  - ip_range: 192.168.1.0/24
    ports: [80, 443]
```

### LLM Configuration (`config/llm.yaml`)
```yaml
endpoint: http://localhost:1234/v1
model: Dolphin-2.9.2-Llama3-8B
max_tokens: 4096
timeout: 30
retry_attempts: 3
concurrency_limit: 2
```

## Testing
```bash
# Run against DVWA
pytest tests/integration/test_dvwa.py

# Replay recorded tool outputs
pytest tests/unit --vcr-record=none

# Benchmark FP/TP rates
python tests/benchmark.py
```

## License
MIT License - For authorized security testing only

## Disclaimer
This tool is designed for authorized security testing and bug bounty programs only. 
Always obtain explicit written permission before testing any target.