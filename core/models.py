"""
Pydantic models for strict validation between components
"""
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, HttpUrl, validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    NEW = "new"
    TRIAGING = "triaging"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    REMEDIATED = "remediated"


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ToolType(str, Enum):
    RECON = "recon"
    SCANNER = "scanner"
    EXPLOIT = "exploit"
    VALIDATOR = "validator"
    CUSTOM = "custom"


# === Target & Scope Models ===

class Target(BaseModel):
    """Represents a scan target"""
    id: Optional[str] = None
    domain: str
    subdomains: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=lambda: [80, 443])
    ip_ranges: List[str] = Field(default_factory=list)
    rate_limit: int = 10
    max_depth: int = 3
    
    @validator('domain')
    def validate_domain(cls, v):
        if not v or len(v) < 3:
            raise ValueError("Invalid domain")
        return v.lower().strip()


class ScopeConfig(BaseModel):
    """Scope configuration for a job"""
    allowed_domains: List[str]
    allowed_ips: List[str] = Field(default_factory=list)
    excluded_endpoints: List[str] = Field(default_factory=list)
    rate_limit_rps: int = 10
    respect_robots_txt: bool = True


# === Job & Task Models ===

class ScanJob(BaseModel):
    """Represents a security scan job"""
    id: str
    target: Target
    scope: ScopeConfig
    status: JobStatus = JobStatus.PENDING
    tools: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: float = 0.0
    error_message: Optional[str] = None


class TaskResult(BaseModel):
    """Result from a tool execution"""
    task_id: str
    tool_name: str
    success: bool
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    output_file: Optional[str] = None
    duration_seconds: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# === Vulnerability & Finding Models ===

class Finding(BaseModel):
    """Represents a security finding"""
    id: str
    job_id: str
    title: str
    description: str
    severity: Severity
    status: FindingStatus = FindingStatus.NEW
    confidence_score: int = Field(ge=0, le=100, default=50)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cwe_ids: List[str] = Field(default_factory=list)
    affected_endpoint: str
    proof_of_concept: str = ""
    remediation: str = ""
    raw_evidence: Dict[str, Any] = Field(default_factory=dict)
    sha256_hash: Optional[str] = None  # For deduplication
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    reviewed_by: Optional[str] = None
    review_notes: Optional[str] = None


class FindingSummary(BaseModel):
    """Aggregated finding statistics"""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    confirmed: int = 0
    false_positives: int = 0


# === LLM Models ===

class LLMRequest(BaseModel):
    """Request to LLM endpoint"""
    messages: List[Dict[str, str]]
    model: str = "Dolphin-2.9.2-Llama3-8B"
    temperature: float = 0.1
    max_tokens: int = 4096
    top_p: float = 0.95
    stream: bool = False


class LLMResponse(BaseModel):
    """Response from LLM endpoint"""
    content: str
    model: str
    usage: Dict[str, int] = Field(default_factory=dict)
    finish_reason: Optional[str] = None


class AnalysisTask(BaseModel):
    """Task for LLM analysis"""
    task_type: str  # recon, enumeration, validation, report
    input_data: str
    context: Optional[str] = None
    expected_output: str  # JSON schema description


# === Report Models ===

class ReportSection(BaseModel):
    """A section of the report"""
    title: str
    content: str
    order: int = 0


class ReportMetadata(BaseModel):
    """Report metadata"""
    job_id: str
    target: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    findings_count: int
    severity_breakdown: Dict[str, int]
    scan_duration_seconds: float
    tools_used: List[str]


class ExportFormat(str, Enum):
    HTML = "html"
    JSON = "json"
    MARKDOWN = "markdown"
    PDF = "pdf"
    TXT = "txt"


# === Audit & Log Models ===

class AuditLog(BaseModel):
    """Immutable audit log entry"""
    id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    action: str
    target: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None


class CommandLog(BaseModel):
    """Logged command execution"""
    command: str
    arguments: List[str] = Field(default_factory=list)
    working_dir: str
    sandbox_id: Optional[str] = None
    executed_at: datetime = Field(default_factory=datetime.utcnow)
    blocked: bool = False
    block_reason: Optional[str] = None


# === Dashboard Models ===

class DashboardStats(BaseModel):
    """Real-time dashboard statistics"""
    active_jobs: int
    queued_jobs: int
    completed_jobs_today: int
    total_findings: int
    pending_reviews: int
    queue_depth: int
    llm_latency_ms: float
    error_rate: float


class SSELogEvent(BaseModel):
    """Server-sent event for log streaming"""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    level: str
    component: str
    message: str
    data: Optional[Dict[str, Any]] = None
