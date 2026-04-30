"""
Database layer for state management and findings storage
Uses SQLite with SQLAlchemy async support
"""
import asyncio
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from sqlalchemy import (
    create_engine, Column, String, Text, Integer, Float, 
    DateTime, ForeignKey, Boolean, Index, event
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.sql import func

Base = declarative_base()


# === Database Models ===

class Job(Base):
    """Scan job database model"""
    __tablename__ = "jobs"
    
    id = Column(String, primary_key=True)
    target_domain = Column(String, nullable=False)
    target_config = Column(Text)  # JSON serialized
    scope_config = Column(Text)  # JSON serialized
    status = Column(String, default="pending")
    tools = Column(Text)  # JSON serialized array
    progress = Column(Float, default=0.0)
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    findings = relationship("Finding", back_populates="job", cascade="all, delete-orphan")
    task_results = relationship("TaskResult", back_populates="job", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_jobs_status', 'status'),
        Index('idx_jobs_created', 'created_at'),
    )


class Finding(Base):
    """Vulnerability finding database model"""
    __tablename__ = "findings"
    
    id = Column(String, primary_key=True)
    job_id = Column(String, ForeignKey('jobs.id'), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String, nullable=False)
    status = Column(String, default="new")
    confidence_score = Column(Integer, default=50)
    cvss_score = Column(Float)
    cwe_ids = Column(Text)  # JSON serialized array
    affected_endpoint = Column(String)
    proof_of_concept = Column(Text)
    remediation = Column(Text)
    raw_evidence = Column(Text)  # JSON serialized
    sha256_hash = Column(String, index=True)  # For deduplication
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    reviewed_by = Column(String)
    review_notes = Column(Text)
    
    job = relationship("Job", back_populates="findings")
    
    __table_args__ = (
        Index('idx_findings_severity', 'severity'),
        Index('idx_findings_status', 'status'),
        Index('idx_findings_job', 'job_id'),
    )


class TaskResult(Base):
    """Tool execution result database model"""
    __tablename__ = "task_results"
    
    id = Column(String, primary_key=True)
    job_id = Column(String, ForeignKey('jobs.id'), nullable=False)
    tool_name = Column(String, nullable=False)
    success = Column(Boolean, default=False)
    exit_code = Column(Integer, default=0)
    stdout = Column(Text)
    stderr = Column(Text)
    output_file = Column(String)
    duration_seconds = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    job = relationship("Job", back_populates="task_results")
    
    __table_args__ = (
        Index('idx_task_results_job', 'job_id'),
        Index('idx_task_results_tool', 'tool_name'),
    )


class AuditLog(Base):
    """Immutable audit log database model"""
    __tablename__ = "audit_logs"
    
    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    event_type = Column(String, nullable=False)
    user_id = Column(String)
    session_id = Column(String)
    action = Column(String, nullable=False)
    target = Column(String)
    details = Column(Text)  # JSON serialized
    ip_address = Column(String)
    
    __table_args__ = (
        Index('idx_audit_timestamp', 'timestamp'),
        Index('idx_audit_event', 'event_type'),
    )


class FindingCache(Base):
    """Deduplication cache for findings"""
    __tablename__ = "finding_cache"
    
    sha256_hash = Column(String, primary_key=True)
    finding_id = Column(String, nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    occurrence_count = Column(Integer, default=1)


# === Database Manager ===

class DatabaseManager:
    """Async database manager for SQLite"""
    
    def __init__(self, db_path: str = "/workspace/data/bugbounty.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.async_engine = None
        self.async_session_maker = None
        self.sync_engine = None
        
    def _get_async_url(self) -> str:
        return f"sqlite+aiosqlite:///{self.db_path}"
    
    def _get_sync_url(self) -> str:
        return f"sqlite:///{self.db_path}"
    
    async def initialize(self):
        """Initialize async database connection"""
        self.async_engine = create_async_engine(
            self._get_async_url(),
            echo=False,
            future=True
        )
        self.async_session_maker = async_sessionmaker(
            self.async_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Create tables
        async with self.async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    def initialize_sync(self):
        """Initialize sync database connection (for non-async contexts)"""
        self.sync_engine = create_engine(
            self._get_sync_url(),
            echo=False,
            connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(self.sync_engine)
        return sessionmaker(bind=self.sync_engine)
    
    @asynccontextmanager
    async def get_session(self):
        """Get async database session"""
        if not self.async_session_maker:
            await self.initialize()
        async with self.async_session_maker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
    
    async def create_job(self, job_data: Dict[str, Any]) -> Job:
        """Create a new scan job"""
        async with self.get_session() as session:
            job = Job(
                id=job_data["id"],
                target_domain=job_data["target"]["domain"],
                target_config=json.dumps(job_data["target"]),
                scope_config=json.dumps(job_data["scope"]),
                status=job_data.get("status", "pending"),
                tools=json.dumps(job_data.get("tools", [])),
                progress=job_data.get("progress", 0.0)
            )
            session.add(job)
            await session.flush()
            return job
    
    async def update_job_status(self, job_id: str, status: str, **kwargs):
        """Update job status and optional fields"""
        async with self.get_session() as session:
            job = session.query(Job).filter(Job.id == job_id).first()
            if job:
                job.status = status
                if status == "running" and not job.started_at:
                    job.started_at = datetime.utcnow()
                elif status in ["completed", "failed", "cancelled"]:
                    job.completed_at = datetime.utcnow()
                for key, value in kwargs.items():
                    if hasattr(job, key):
                        setattr(job, key, value)
                await session.flush()
    
    async def create_finding(self, finding_data: Dict[str, Any]) -> Finding:
        """Create a new finding"""
        async with self.get_session() as session:
            # Generate SHA-256 hash for deduplication
            dedup_string = f"{finding_data['job_id']}|{finding_data['affected_endpoint']}|{finding_data['title']}"
            sha256_hash = hashlib.sha256(dedup_string.encode()).hexdigest()
            
            finding = Finding(
                id=finding_data["id"],
                job_id=finding_data["job_id"],
                title=finding_data["title"],
                description=finding_data.get("description", ""),
                severity=finding_data["severity"],
                confidence_score=finding_data.get("confidence_score", 50),
                cvss_score=finding_data.get("cvss_score"),
                cwe_ids=json.dumps(findings_data.get("cwe_ids", [])),
                affected_endpoint=finding_data["affected_endpoint"],
                proof_of_concept=finding_data.get("proof_of_concept", ""),
                remediation=finding_data.get("remediation", ""),
                raw_evidence=json.dumps(findings_data.get("raw_evidence", {})),
                sha256_hash=sha256_hash
            )
            session.add(finding)
            await session.flush()
            return finding
    
    async def check_finding_duplicate(self, sha256_hash: str) -> bool:
        """Check if a finding with this hash already exists"""
        async with self.get_session() as session:
            result = session.query(Finding).filter(
                Finding.sha256_hash == sha256_hash
            ).first()
            return result is not None
    
    async def add_task_result(self, task_data: Dict[str, Any]) -> TaskResult:
        """Add a task execution result"""
        async with self.get_session() as session:
            task = TaskResult(
                id=task_data["task_id"],
                job_id=task_data["job_id"],
                tool_name=task_data["tool_name"],
                success=task_data["success"],
                exit_code=task_data.get("exit_code", 0),
                stdout=task_data.get("stdout", ""),
                stderr=task_data.get("stderr", ""),
                output_file=task_data.get("output_file"),
                duration_seconds=task_data.get("duration_seconds", 0.0)
            )
            session.add(task)
            await session.flush()
            return task
    
    async def log_audit_event(self, event_data: Dict[str, Any]) -> AuditLog:
        """Add an immutable audit log entry"""
        async with self.get_session() as session:
            audit = AuditLog(
                id=event_data.get("id", hashlib.sha256(
                    f"{datetime.utcnow().isoformat()}|{event_data['action']}".encode()
                ).hexdigest()),
                event_type=event_data["event_type"],
                user_id=event_data.get("user_id"),
                session_id=event_data.get("session_id"),
                action=event_data["action"],
                target=event_data.get("target"),
                details=json.dumps(event_data.get("details", {})),
                ip_address=event_data.get("ip_address")
            )
            session.add(audit)
            await session.flush()
            return audit
    
    async def get_job(self, job_id: str) -> Optional[Job]:
        """Get a job by ID"""
        async with self.get_session() as session:
            return session.query(Job).filter(Job.id == job_id).first()
    
    async def get_job_findings(self, job_id: str) -> List[Finding]:
        """Get all findings for a job"""
        async with self.get_session() as session:
            return session.query(Finding).filter(
                Finding.job_id == job_id
            ).all()
    
    async def get_active_jobs(self) -> List[Job]:
        """Get all active (running/paused) jobs"""
        async with self.get_session() as session:
            return session.query(Job).filter(
                Job.status.in_(["running", "paused"])
            ).all()
    
    async def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get statistics for dashboard"""
        async with self.get_session() as session:
            stats = {
                "active_jobs": session.query(Job).filter(
                    Job.status.in_(["running", "paused"])
                ).count(),
                "queued_jobs": session.query(Job).filter(
                    Job.status == "pending"
                ).count(),
                "completed_jobs_today": session.query(Job).filter(
                    Job.status == "completed",
                    func.date(Job.completed_at) == func.date(datetime.utcnow())
                ).count(),
                "total_findings": session.query(Finding).count(),
                "pending_reviews": session.query(Finding).filter(
                    Finding.status == "new",
                    Finding.severity.in_(["critical", "high"])
                ).count(),
            }
            return stats


# Global database instance
db_manager = DatabaseManager()
