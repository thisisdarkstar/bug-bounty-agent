"""
Report generator - Multi-format report generation
HTML, JSON, Markdown, PDF, TXT exports with Jinja2 templates
"""
import os
import json
import gzip
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from jinja2 import Environment, FileSystemLoader, select_autoescape


async def generate_full_report(
    job_id: str,
    target: str,
    findings: List[Dict[str, Any]],
    tool_outputs: List[Dict[str, Any]],
    output_dir: str = None
) -> str:
    """
    Generate complete security assessment report in multiple formats
    
    Args:
        job_id: Job identifier
        target: Target domain
        findings: List of confirmed findings
        tool_outputs: Raw tool output data
        output_dir: Directory to save reports (defaults to project_root/reports)
        
    Returns:
        Path to the main HTML report
    """
    if output_dir is None:
        # Use relative path from project root
        project_root = Path(__file__).parent.parent
        output_dir = str(project_root / "reports")
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Prepare report data
    report_data = {
        "job_id": job_id,
        "target": target,
        "generated_at": datetime.utcnow().isoformat(),
        "findings": findings,
        "tool_outputs": tool_outputs,
        "summary": generate_summary(findings)
    }
    
    # Generate all formats
    html_path = await generate_html_report(report_data, output_path)
    await generate_json_report(report_data, output_path)
    await generate_markdown_report(report_data, output_path)
    await generate_txt_report(report_data, output_path)
    
    # Compress raw logs
    await compress_raw_logs(tool_outputs, output_path / f"{job_id}_raw_logs.json.gz")
    
    return str(html_path)


def generate_summary(findings: List[Dict]) -> Dict[str, Any]:
    """Generate finding summary statistics"""
    summary = {
        "total": len(findings),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for finding in findings:
        severity = finding.get("severity", "info").lower()
        if severity in summary:
            summary[severity] += 1
    
    # Calculate risk score
    risk_score = (
        summary["critical"] * 10 +
        summary["high"] * 5 +
        summary["medium"] * 2 +
        summary["low"] * 1
    )
    summary["risk_score"] = min(risk_score, 100)
    
    return summary


async def generate_html_report(report_data: Dict, output_path: Path) -> Path:
    """Generate HTML report with responsive design"""
    template_dir = Path(__file__).parent.parent / "templates"
    
    # Create templates directory if it doesn't exist
    template_dir.mkdir(parents=True, exist_ok=True)
    
    # Create default template if not exists
    template_file = template_dir / "report.html.j2"
    if not template_file.exists():
        await create_default_html_template(template_file)
    
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(['html', 'xml'])
    )
    
    template = env.get_template("report.html.j2")
    
    html_content = template.render(
        **report_data,
        severity_colors={
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d"
        }
    )
    
    output_file = output_path / f"{report_data['job_id']}_report.html"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_file


async def generate_json_report(report_data: Dict, output_path: Path) -> Path:
    """Generate structured JSON report"""
    output_file = output_path / f"{report_data['job_id']}_report.json"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, default=str)
    
    return output_file


async def generate_markdown_report(report_data: Dict, output_path: Path) -> Path:
    """Generate Markdown report"""
    template_dir = Path(__file__).parent.parent / "templates"
    template_dir.mkdir(parents=True, exist_ok=True)
    
    template_file = template_dir / "report.md.j2"
    if not template_file.exists():
        await create_default_md_template(template_file)
    
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template("report.md.j2")
    
    md_content = template.render(**report_data)
    
    output_file = output_path / f"{report_data['job_id']}_report.md"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(md_content)
    
    return output_file


async def generate_txt_report(report_data: Dict, output_path: Path) -> Path:
    """Generate plain text report"""
    lines = []
    lines.append("=" * 80)
    lines.append(f"SECURITY ASSESSMENT REPORT")
    lines.append("=" * 80)
    lines.append(f"\nTarget: {report_data['target']}")
    lines.append(f"Job ID: {report_data['job_id']}")
    lines.append(f"Generated: {report_data['generated_at']}")
    lines.append(f"\n{'=' * 80}")
    lines.append("EXECUTIVE SUMMARY")
    lines.append("=" * 80)
    
    summary = report_data['summary']
    lines.append(f"\nTotal Findings: {summary['total']}")
    lines.append(f"Risk Score: {summary['risk_score']}/100")
    lines.append(f"\nSeverity Breakdown:")
    lines.append(f"  Critical: {summary['critical']}")
    lines.append(f"  High:     {summary['high']}")
    lines.append(f"  Medium:   {summary['medium']}")
    lines.append(f"  Low:      {summary['low']}")
    lines.append(f"  Info:     {summary['info']}")
    
    lines.append(f"\n{'=' * 80}")
    lines.append("FINDINGS")
    lines.append("=" * 80)
    
    for i, finding in enumerate(report_data['findings'], 1):
        lines.append(f"\n[{i}] {finding['title'].upper()}")
        lines.append(f"    Severity: {finding['severity'].upper()}")
        lines.append(f"    Status: {finding['status']}")
        lines.append(f"    Confidence: {finding.get('confidence_score', 'N/A')}%")
        lines.append(f"    Endpoint: {finding.get('affected_endpoint', 'N/A')}")
        lines.append(f"\n    Description:")
        for line in finding.get('description', 'No description').split('\n'):
            lines.append(f"      {line}")
        
        if finding.get('proof_of_concept'):
            lines.append(f"\n    Proof of Concept:")
            for line in finding['proof_of_concept'].split('\n'):
                lines.append(f"      {line}")
        
        if finding.get('remediation'):
            lines.append(f"\n    Remediation:")
            for line in finding['remediation'].split('\n'):
                lines.append(f"      {line}")
        
        lines.append("-" * 40)
    
    output_file = output_path / f"{report_data['job_id']}_report.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    
    return output_file


async def compress_raw_logs(tool_outputs: List[Dict], output_file: Path) -> Path:
    """Compress raw tool outputs with gzip"""
    content = json.dumps(tool_outputs, indent=2, default=str)
    
    with gzip.open(output_file, 'wt', encoding='utf-8') as f:
        f.write(content)
    
    return output_file


async def create_default_html_template(template_file: Path):
    """Create default HTML report template"""
    template_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {{ target }}</title>
    <style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #17a2b8;
            --info: #6c757d;
        }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid var(--critical); padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { padding: 20px; border-radius: 8px; color: white; text-align: center; }
        .stat-card.critical { background: var(--critical); }
        .stat-card.high { background: var(--high); }
        .stat-card.medium { background: var(--medium); color: #333; }
        .stat-card.low { background: var(--low); }
        .stat-card.info { background: var(--info); }
        .finding { border: 1px solid #ddd; border-radius: 8px; margin: 20px 0; overflow: hidden; }
        .finding-header { padding: 15px 20px; background: #f8f9fa; border-bottom: 1px solid #ddd; display: flex; justify-content: space-between; align-items: center; }
        .finding-body { padding: 20px; }
        .severity-badge { padding: 4px 12px; border-radius: 20px; color: white; font-size: 12px; font-weight: bold; text-transform: uppercase; }
        .poc-box { background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 4px; font-family: 'Consolas', monospace; overflow-x: auto; margin: 10px 0; }
        .meta { color: #666; font-size: 14px; }
        details { margin: 10px 0; }
        summary { cursor: pointer; color: #0066cc; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Assessment Report</h1>
        
        <div class="meta">
            <p><strong>Target:</strong> {{ target }}</p>
            <p><strong>Job ID:</strong> {{ job_id }}</p>
            <p><strong>Generated:</strong> {{ generated_at }}</p>
        </div>
        
        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="stat-card critical">
                <div style="font-size: 32px; font-weight: bold;">{{ summary.critical }}</div>
                <div>Critical</div>
            </div>
            <div class="stat-card high">
                <div style="font-size: 32px; font-weight: bold;">{{ summary.high }}</div>
                <div>High</div>
            </div>
            <div class="stat-card medium">
                <div style="font-size: 32px; font-weight: bold;">{{ summary.medium }}</div>
                <div>Medium</div>
            </div>
            <div class="stat-card low">
                <div style="font-size: 32px; font-weight: bold;">{{ summary.low }}</div>
                <div>Low</div>
            </div>
            <div class="stat-card info">
                <div style="font-size: 32px; font-weight: bold;">{{ summary.info }}</div>
                <div>Info</div>
            </div>
        </div>
        
        <p><strong>Risk Score:</strong> {{ summary.risk_score }}/100</p>
        <p><strong>Total Findings:</strong> {{ summary.total }}</p>
        
        <h2>Findings</h2>
        {% for finding in findings %}
        <div class="finding">
            <div class="finding-header">
                <strong>{{ finding.title }}</strong>
                <span class="severity-badge" style="background: var(--{{ finding.severity }});">{{ finding.severity }}</span>
            </div>
            <div class="finding-body">
                <p><strong>Status:</strong> {{ finding.status }} | <strong>Confidence:</strong> {{ finding.get('confidence_score', 'N/A') }}%</p>
                <p><strong>Endpoint:</strong> {{ finding.get('affected_endpoint', 'N/A') }}</p>
                
                <h4>Description</h4>
                <p>{{ finding.description }}</p>
                
                {% if finding.get('proof_of_concept') %}
                <h4>Proof of Concept</h4>
                <div class="poc-box">{{ finding.proof_of_concept }}</div>
                {% endif %}
                
                {% if finding.get('remediation') %}
                <h4>Remediation</h4>
                <p>{{ finding.remediation }}</p>
                {% endif %}
                
                {% if finding.get('cwe_ids') %}
                <details>
                    <summary>CWE References</summary>
                    <p>{{ finding.cwe_ids | join(', ') }}</p>
                </details>
                {% endif %}
            </div>
        </div>
        {% endfor %}
        
        <div class="meta" style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd;">
            <p>Generated by Bug Bounty Agent v0.1.0</p>
        </div>
    </div>
</body>
</html>'''
    
    with open(template_file, 'w', encoding='utf-8') as f:
        f.write(template_content)


async def create_default_md_template(template_file: Path):
    """Create default Markdown report template"""
    template_content = '''# Security Assessment Report

**Target:** {{ target }}  
**Job ID:** {{ job_id }}  
**Generated:** {{ generated_at }}

---

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {{ summary.critical }} |
| 🟠 High | {{ summary.high }} |
| 🟡 Medium | {{ summary.medium }} |
| 🔵 Low | {{ summary.low }} |
| ⚪ Info | {{ summary.info }} |

**Risk Score:** {{ summary.risk_score }}/100  
**Total Findings:** {{ summary.total }}

---

## Findings

{% for finding in findings %}
### {{ finding.title }}

**Severity:** {{ finding.severity | upper }}  
**Status:** {{ finding.status }}  
**Confidence:** {{ finding.get('confidence_score', 'N/A') }}%  
**Endpoint:** {{ finding.get('affected_endpoint', 'N/A') }}

#### Description

{{ finding.description }}

{% if finding.get('proof_of_concept') %}
#### Proof of Concept

```
{{ finding.proof_of_concept }}
```
{% endif %}

{% if finding.get('remediation') %}
#### Remediation

{{ finding.remediation }}
{% endif %}

---

{% endfor %}

---

*Generated by Bug Bounty Agent v0.1.0*
'''
    
    with open(template_file, 'w', encoding='utf-8') as f:
        f.write(template_content)
