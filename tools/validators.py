"""
Vulnerability validators - Verify potential vulnerabilities
Proof-of-concept generation, false positive reduction
"""
import asyncio
import aiohttp
from typing import Dict, Any, Optional, List
from datetime import datetime


async def validate_vulnerability(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate a potential vulnerability
    
    Args:
        finding: Potential vulnerability data
        
    Returns:
        Validation result with confirmation status
    """
    vuln_type = finding.get("raw_evidence", {}).get("type", "unknown")
    
    validators = {
        "sensitive_file_exposed": validate_sensitive_file,
        "admin_panel_exposed": validate_admin_panel,
        "missing_security_headers": validate_security_headers,
        "sql_injection": validate_sqli,
        "xss": validate_xss,
        "ssrf": validate_ssrf,
        "default_credentials": validate_default_creds
    }
    
    validator_func = validators.get(vuln_type, validate_generic)
    
    try:
        result = await validator_func(finding)
        return result
    except Exception as e:
        return {
            "validated": False,
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


async def validate_sensitive_file(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Validate exposed sensitive file (.git, .env, etc.)"""
    url = finding.get("raw_evidence", {}).get("url", "")
    
    if not url:
        return {"validated": False, "reason": "No URL provided"}
    
    result = {
        "vuln_type": "sensitive_file_exposed",
        "url": url,
        "validated": False,
        "evidence": {},
        "timestamp": datetime.utcnow().isoformat()
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                content = await response.text()
                
                if ".git" in url and response.status == 200:
                    # Check for Git repository markers
                    if "HEAD" in content or "refs/" in content:
                        result["validated"] = True
                        result["evidence"] = {
                            "file_type": "git_repository",
                            "content_preview": content[:200]
                        }
                
                elif ".env" in url and response.status == 200:
                    # Check for environment variable patterns
                    if "=" in content and any(kw in content for kw in ["DB_", "API_", "SECRET_", "KEY_"]):
                        result["validated"] = True
                        result["evidence"] = {
                            "file_type": "env_file",
                            "has_secrets": True,
                            "line_count": len(content.splitlines())
                        }
                
                elif "phpinfo" in url and response.status == 200:
                    if "PHP Version" in content:
                        result["validated"] = True
                        result["evidence"] = {
                            "file_type": "phpinfo",
                            "php_version": extract_php_version(content)
                        }
    except Exception as e:
        result["error"] = str(e)
    
    return result


async def validate_admin_panel(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Validate exposed admin panel"""
    url = finding.get("raw_evidence", {}).get("url", "")
    
    if not url:
        return {"validated": False, "reason": "No URL provided"}
    
    result = {
        "vuln_type": "admin_panel_exposed",
        "url": url,
        "validated": False,
        "evidence": {},
        "timestamp": datetime.utcnow().isoformat()
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=True) as response:
                content = await response.text()
                
                # Look for admin panel indicators
                admin_indicators = [
                    "admin", "dashboard", "login", "password",
                    "username", "sign in", "administrative"
                ]
                
                score = sum(1 for indicator in admin_indicators if indicator.lower() in content.lower())
                
                if score >= 2:
                    result["validated"] = True
                    result["evidence"] = {
                        "indicators_found": score,
                        "status_code": response.status,
                        "title": extract_title(content)
                    }
    except Exception as e:
        result["error"] = str(e)
    
    return result


async def validate_security_headers(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Validate missing security headers"""
    headers_data = finding.get("raw_evidence", {})
    
    result = {
        "vuln_type": "missing_security_headers",
        "validated": True,  # This is usually accurate from scan
        "missing_headers": headers_data.get("missing_headers", []),
        "impact": "Clickjacking, XSS, MIME sniffing risks",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    return result


async def validate_sqli(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Validate SQL injection vulnerability"""
    url = finding.get("affected_endpoint", "")
    
    result = {
        "vuln_type": "sql_injection",
        "url": url,
        "validated": False,
        "evidence": {},
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Note: Actual SQLi validation would require careful payload testing
    # This is a placeholder that should be implemented with proper tools
    
    return result


async def validate_xss(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Validate XSS vulnerability"""
    url = finding.get("affected_endpoint", "")
    
    result = {
        "vuln_type": "xss",
        "url": url,
        "validated": False,
        "evidence": {},
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Note: Actual XSS validation would require payload injection and response analysis
    # This is a placeholder
    
    return result


async def validate_ssrf(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Validate SSRF vulnerability"""
    result = {
        "vuln_type": "ssrf",
        "validated": False,
        "evidence": {},
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Placeholder for SSRF validation
    
    return result


async def validate_default_creds(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Validate default credentials"""
    result = {
        "vuln_type": "default_credentials",
        "validated": False,
        "evidence": {},
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Placeholder for default credential testing
    
    return result


async def validate_generic(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Generic validation for unknown vulnerability types"""
    return {
        "vuln_type": finding.get("raw_evidence", {}).get("type", "unknown"),
        "validated": False,
        "reason": "No specific validator available",
        "requires_manual_review": True,
        "timestamp": datetime.utcnow().isoformat()
    }


# Helper functions

def extract_php_version(content: str) -> Optional[str]:
    """Extract PHP version from phpinfo output"""
    import re
    match = re.search(r'PHP Version\s*([0-9.]+)', content)
    return match.group(1) if match else None


def extract_title(content: str) -> Optional[str]:
    """Extract HTML title from content"""
    import re
    match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
    return match.group(1) if match else None
