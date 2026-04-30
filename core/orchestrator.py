"""
LangGraph-based orchestrator for deterministic security testing workflow
State machine with nodes: Scope Validation → Recon → Enumeration → Validation → Report
"""
import asyncio
import uuid
import json
from datetime import datetime
from typing import TypedDict, List, Dict, Any, Optional, Annotated
from enum import Enum

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from core.models import ScanJob, Target, ScopeConfig, JobStatus, Severity, FindingStatus
from core.database import db_manager
from core.llm_client import llm_client


# === State Definition ===

class WorkflowState(TypedDict):
    """LangGraph workflow state"""
    job_id: str
    target: Dict[str, Any]
    scope: Dict[str, Any]
    current_phase: str
    tool_outputs: Annotated[List[Dict], "append"]
    findings: Annotated[List[Dict], "append"]
    errors: Annotated[List[str], "append"]
    progress: float
    report_generated: bool


# === Phase Handlers ===

async def validate_scope(state: WorkflowState) -> WorkflowState:
    """Phase 1: Validate target against scope configuration"""
    print(f"[{state['job_id']}] Validating scope...")
    
    try:
        # Log audit event
        await db_manager.log_audit_event({
            "event_type": "scope_validation",
            "action": "validate_scope",
            "target": state['target'].get('domain'),
            "details": {"job_id": state['job_id']}
        })
        
        # Basic validation logic
        target_domain = state['target'].get('domain', '')
        allowed_domains = state['scope'].get('allowed_domains', [])
        
        if not target_domain:
            state['errors'].append("No target domain specified")
            return state
        
        # Check if target is in allowed list (simplified)
        is_allowed = any(
            target_domain.endswith(d) or target_domain == d
            for d in allowed_domains
        )
        
        if not is_allowed and allowed_domains:
            state['errors'].append(f"Target {target_domain} not in allowed scope")
            return state
        
        # Update job status
        await db_manager.update_job_status(state['job_id'], 'running')
        
        state['current_phase'] = 'recon'
        state['progress'] = 10.0
        
        print(f"[{state['job_id']}] Scope validated successfully")
        
    except Exception as e:
        state['errors'].append(f"Scope validation failed: {str(e)}")
    
    return state


async def run_recon(state: WorkflowState) -> WorkflowState:
    """Phase 2: Passive reconnaissance"""
    print(f"[{state['job_id']}] Running reconnaissance...")
    
    try:
        from tools.recon_tools import run_subdomain_enum, run_tech_detection
        
        target = state['target'].get('domain')
        
        # Run subdomain enumeration
        subdomain_result = await run_subdomain_enum(target)
        state['tool_outputs'].append({
            "tool": "subdomain_enum",
            "result": subdomain_result,
            "phase": "recon"
        })
        
        # Run technology detection
        tech_result = await run_tech_detection(target)
        state['tool_outputs'].append({
            "tool": "tech_detection",
            "result": tech_result,
            "phase": "recon"
        })
        
        # Analyze recon results with LLM
        recon_summary = await llm_client.analyze_tool_output(
            tool_name="recon_aggregator",
            output=json.dumps(state['tool_outputs'][-2:], indent=2),
            task_type="recon"
        )
        
        # Extract findings from recon
        if 'interesting_findings' in recon_summary:
            for finding in recon_summary.get('recommendations', []):
                state['findings'].append({
                    "id": str(uuid.uuid4()),
                    "job_id": state['job_id'],
                    "title": f"Recon Finding: {finding[:50]}",
                    "description": finding,
                    "severity": "info",
                    "status": "new",
                    "confidence_score": 60,
                    "affected_endpoint": target,
                    "phase": "recon"
                })
        
        state['current_phase'] = 'enumeration'
        state['progress'] = 35.0
        
        print(f"[{state['job_id']}] Reconnaissance complete")
        
    except Exception as e:
        state['errors'].append(f"Reconnaissance failed: {str(e)}")
        state['current_phase'] = 'enumeration'  # Continue anyway
        state['progress'] = 35.0
    
    return state


async def run_enumeration(state: WorkflowState) -> WorkflowState:
    """Phase 3: Active enumeration and scanning"""
    print(f"[{state['job_id']}] Running enumeration...")
    
    try:
        from tools.scanners import run_port_scan, run_web_scan
        
        target = state['target'].get('domain')
        ports = state['target'].get('ports', [80, 443])
        
        # Run port scan
        port_result = await run_port_scan(target, ports)
        state['tool_outputs'].append({
            "tool": "port_scan",
            "result": port_result,
            "phase": "enumeration"
        })
        
        # Run web vulnerability scan
        web_result = await run_web_scan(target)
        state['tool_outputs'].append({
            "tool": "web_scan",
            "result": web_result,
            "phase": "enumeration"
        })
        
        # Analyze enumeration results with LLM
        enum_analysis = await llm_client.analyze_tool_output(
            tool_name="enumeration_aggregator",
            output=json.dumps(state['tool_outputs'][-2:], indent=2),
            task_type="enumeration"
        )
        
        # Extract potential vulnerabilities
        for vuln in enum_analysis.get('potential_vulnerabilities', []):
            state['findings'].append({
                "id": str(uuid.uuid4()),
                "job_id": state['job_id'],
                "title": vuln.get('title', 'Unknown Vulnerability'),
                "description": vuln.get('description', ''),
                "severity": vuln.get('severity', 'medium'),
                "status": "new",
                "confidence_score": vuln.get('confidence', 50),
                "affected_endpoint": target,
                "raw_evidence": vuln.get('evidence', {}),
                "phase": "enumeration"
            })
        
        state['current_phase'] = 'validation'
        state['progress'] = 65.0
        
        print(f"[{state['job_id']}] Enumeration complete")
        
    except Exception as e:
        state['errors'].append(f"Enumeration failed: {str(e)}")
        state['current_phase'] = 'validation'
        state['progress'] = 65.0
    
    return state


async def run_validation(state: WorkflowState) -> WorkflowState:
    """Phase 4: Vulnerability validation"""
    print(f"[{state['job_id']}] Validating vulnerabilities...")
    
    try:
        from tools.validators import validate_vulnerability
        
        # Validate each potential finding
        validated_count = 0
        for finding in state['findings']:
            if finding.get('phase') == 'enumeration':
                validation_result = await validate_vulnerability(finding)
                
                # Use LLM to assess validation results
                llm_assessment = await llm_client.analyze_tool_output(
                    tool_name="validation_assessor",
                    output=json.dumps(validation_result, indent=2),
                    task_type="validation"
                )
                
                if llm_assessment.get('is_valid', False):
                    finding['status'] = 'confirmed'
                    finding['confidence_score'] = llm_assessment.get('confidence_score', 70)
                    finding['proof_of_concept'] = llm_assessment.get('proof_of_concept', '')
                    finding['remediation'] = llm_assessment.get('remediation', '')
                    finding['cwe_ids'] = llm_assessment.get('cwe_ids', [])
                    finding['cvss_score'] = llm_assessment.get('cvss_estimate')
                    validated_count += 1
                else:
                    finding['status'] = 'false_positive'
                    finding['review_notes'] = str(llm_assessment.get('false_positive_indicators', []))
        
        state['current_phase'] = 'reporting'
        state['progress'] = 85.0
        
        print(f"[{state['job_id']}] Validation complete ({validated_count} confirmed)")
        
    except Exception as e:
        state['errors'].append(f"Validation failed: {str(e)}")
        state['current_phase'] = 'reporting'
        state['progress'] = 85.0
    
    return state


async def generate_report(state: WorkflowState) -> WorkflowState:
    """Phase 5: Generate final report"""
    print(f"[{state['job_id']}] Generating report...")
    
    try:
        from agents.report_generator import generate_full_report
        
        # Filter confirmed findings
        confirmed_findings = [
            f for f in state['findings'] 
            if f.get('status') != 'false_positive'
        ]
        
        # Generate report
        report_path = await generate_full_report(
            job_id=state['job_id'],
            target=state['target'].get('domain'),
            findings=confirmed_findings,
            tool_outputs=state['tool_outputs']
        )
        
        state['report_generated'] = True
        state['progress'] = 100.0
        
        # Update job as completed
        await db_manager.update_job_status(
            state['job_id'], 
            'completed',
            progress=100.0
        )
        
        # Save findings to database
        for finding in confirmed_findings:
            try:
                await db_manager.create_finding(finding)
            except Exception as e:
                state['errors'].append(f"Failed to save finding: {str(e)}")
        
        print(f"[{state['job_id']}] Report generated: {report_path}")
        
    except Exception as e:
        state['errors'].append(f"Report generation failed: {str(e)}")
        state['progress'] = 90.0
    
    return state


# === Workflow Builder ===

class SecurityWorkflow:
    """LangGraph-based security testing workflow"""
    
    def __init__(self):
        self.graph = None
        self.memory = MemorySaver()
        self._build_graph()
    
    def _build_graph(self):
        """Build the LangGraph state machine"""
        workflow = StateGraph(WorkflowState)
        
        # Add nodes
        workflow.add_node("validate_scope", validate_scope)
        workflow.add_node("run_recon", run_recon)
        workflow.add_node("run_enumeration", run_enumeration)
        workflow.add_node("run_validation", run_validation)
        workflow.add_node("generate_report", generate_report)
        
        # Set entry point
        workflow.set_entry_point("validate_scope")
        
        # Define edges (deterministic flow)
        workflow.add_edge("validate_scope", "run_recon")
        workflow.add_edge("run_recon", "run_enumeration")
        workflow.add_edge("run_enumeration", "run_validation")
        workflow.add_edge("run_validation", "generate_report")
        workflow.add_edge("generate_report", END)
        
        # Compile with memory
        self.graph = workflow.compile(checkpointer=self.memory)
    
    async def execute(self, job: ScanJob) -> WorkflowState:
        """Execute the workflow for a job"""
        
        # Initialize state
        initial_state = WorkflowState(
            job_id=job.id,
            target=job.target.model_dump(),
            scope=job.scope.model_dump(),
            current_phase="validate_scope",
            tool_outputs=[],
            findings=[],
            errors=[],
            progress=0.0,
            report_generated=False
        )
        
        # Execute workflow
        config = {"configurable": {"thread_id": job.id}}
        final_state = await self.graph.ainvoke(initial_state, config=config)
        
        return final_state
    
    async def execute_from_dict(self, job_data: Dict[str, Any]) -> WorkflowState:
        """Execute workflow from dictionary data"""
        job = ScanJob(
            id=job_data["id"],
            target=Target(**job_data["target"]),
            scope=ScopeConfig(**job_data["scope"]),
            tools=job_data.get("tools", [])
        )
        return await self.execute(job)


# Global workflow instance
workflow = SecurityWorkflow()
