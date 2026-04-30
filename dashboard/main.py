"""
FastAPI Dashboard Backend with SSE support for real-time log streaming
"""
import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from core.database import db_manager, Job
from core.models import ScanJob, Target, ScopeConfig, JobStatus
from core.orchestrator import workflow


# === Application Setup ===

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    # Startup
    print("🚀 Starting Bug Bounty Agent Dashboard...")
    await db_manager.initialize()
    print("✅ Database initialized")
    yield
    # Shutdown
    print("👋 Shutting down...")


app = FastAPI(
    title="Bug Bounty Agent",
    description="Autonomous Security Testing Platform",
    version="1.0.0",
    lifespan=lifespan
)

# Templates and static files
templates_path = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_path))


# === Request/Response Models ===

class CreateJobRequest(BaseModel):
    target_domain: str
    allowed_domains: List[str] = []
    ports: List[int] = [80, 443]
    rate_limit: int = 10


class JobResponse(BaseModel):
    id: str
    target_domain: str
    status: str
    progress: float
    created_at: datetime


# === SSE Event Generator ===

active_subscribers: List[asyncio.Queue] = []


async def sse_generator():
    """Server-Sent Events generator for real-time updates"""
    queue = asyncio.Queue()
    active_subscribers.append(queue)
    
    try:
        while True:
            event = await queue.get()
            yield f"data: {event}\n\n"
    except GeneratorExit:
        active_subscribers.remove(queue)


async def broadcast_event(event_data: Dict[str, Any]):
    """Broadcast event to all SSE subscribers"""
    import json as json_lib
    event_dict = {"timestamp": datetime.utcnow().isoformat(), **event_data}
    event_json = json_lib.dumps(event_dict)
    for queue in active_subscribers:
        await queue.put(event_json)


# === API Endpoints ===

@app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    """Main dashboard page"""
    return templates.TemplateResponse(request, "dashboard.html", {"title": "Bug Bounty Agent"})


@app.get("/api/stats")
async def get_stats():
    """Get dashboard statistics"""
    # Ensure database is initialized
    if not db_manager.async_session_maker:
        await db_manager.initialize()
    stats = await db_manager.get_dashboard_stats()
    return JSONResponse(content=stats)


@app.get("/api/jobs")
async def list_jobs():
    """List all scan jobs"""
    from sqlalchemy import select
    
    # Ensure database is initialized
    if not db_manager.async_session_maker:
        await db_manager.initialize()
    
    async with db_manager.get_session() as session:
        stmt = select(Job).order_by(Job.created_at.desc()).limit(50)
        result = await session.execute(stmt)
        jobs = result.scalars().all()
        
        return {
            "jobs": [
                {
                    "id": job.id,
                    "target_domain": job.target_domain,
                    "status": job.status,
                    "progress": job.progress,
                    "created_at": job.created_at.isoformat(),
                    "completed_at": job.completed_at.isoformat() if job.completed_at else None
                }
                for job in jobs
            ]
        }


@app.post("/api/jobs", response_model=JobResponse)
async def create_job(job_request: CreateJobRequest, background_tasks: BackgroundTasks):
    """Create a new scan job"""
    job_id = str(uuid.uuid4())
    
    # Create job in database
    job_data = {
        "id": job_id,
        "target": {
            "domain": job_request.target_domain,
            "ports": job_request.ports,
            "rate_limit": job_request.rate_limit
        },
        "scope": {
            "allowed_domains": job_request.allowed_domains or [job_request.target_domain],
            "rate_limit_rps": job_request.rate_limit
        },
        "status": "pending",
        "tools": ["subdomain_enum", "tech_detection", "port_scan", "web_scan"]
    }
    
    await db_manager.create_job(job_data)
    
    # Start workflow in background
    background_tasks.add_task(run_job_workflow, job_data)
    
    # Broadcast event
    await broadcast_event({
        "event": "job_created",
        "job_id": job_id,
        "status": "pending"
    })
    
    return JobResponse(
        id=job_id,
        target_domain=job_request.target_domain,
        status="pending",
        progress=0.0,
        created_at=datetime.utcnow()
    )


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str):
    """Get job details"""
    job = await db_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    findings = await db_manager.get_job_findings(job_id)
    
    return {
        "job": {
            "id": job.id,
            "target_domain": job.target_domain,
            "status": job.status,
            "progress": job.progress,
            "created_at": job.created_at.isoformat(),
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "error_message": job.error_message
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "confidence_score": f.confidence_score,
                "affected_endpoint": f.affected_endpoint
            }
            for f in findings
        ]
    }


@app.post("/api/jobs/{job_id}/cancel")
async def cancel_job(job_id: str):
    """Cancel a running job"""
    job = await db_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job.status not in ["running", "pending"]:
        raise HTTPException(status_code=400, detail=f"Cannot cancel job in {job.status} state")
    
    await db_manager.update_job_status(job_id, "cancelled")
    
    await broadcast_event({
        "event": "job_cancelled",
        "job_id": job_id
    })
    
    return {"message": f"Job {job_id} cancelled"}


@app.get("/api/events")
async def stream_events(request: Request):
    """Server-Sent Events endpoint for real-time updates"""
    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "subscribers": len(active_subscribers)
    }


@app.get("/api/llm/models")
async def get_llm_models(base_url: str, request: Request):
    """Proxy endpoint to fetch available models from LLM server (handles CORS)"""
    import httpx
    
    if not base_url:
        raise HTTPException(status_code=400, detail="base_url parameter is required")
    
    # Get API key from Authorization header if present
    auth_header = request.headers.get("Authorization", "")
    headers = {}
    if auth_header.startswith("Bearer "):
        headers["Authorization"] = auth_header
    
    try:
        async with httpx.AsyncClient(timeout=10.0, headers=headers) as client:
            response = await client.get(f"{base_url}/models")
            response.raise_for_status()
            return response.json()
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Timeout connecting to LLM server")
    except httpx.ConnectError as e:
        raise HTTPException(status_code=503, detail=f"Cannot connect to LLM server: {str(e)}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"LLM server error: {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching models: {str(e)}")


# === Background Task Runner ===

async def run_job_workflow(job_data: Dict[str, Any]):
    """Execute the security workflow for a job"""
    try:
        # Update status to running
        await db_manager.update_job_status(job_data["id"], "running")
        
        await broadcast_event({
            "event": "job_started",
            "job_id": job_data["id"],
            "status": "running"
        })
        
        # Execute workflow
        final_state = await workflow.execute_from_dict(job_data)
        
        # Broadcast completion
        await broadcast_event({
            "event": "job_completed",
            "job_id": job_data["id"],
            "status": "completed",
            "progress": final_state.get("progress", 100),
            "findings_count": len(final_state.get("findings", [])),
            "errors_count": len(final_state.get("errors", []))
        })
        
    except Exception as e:
        print(f"❌ Workflow failed: {e}")
        await db_manager.update_job_status(job_data["id"], "failed", error_message=str(e))
        
        await broadcast_event({
            "event": "job_failed",
            "job_id": job_data["id"],
            "status": "failed",
            "error": str(e)
        })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
