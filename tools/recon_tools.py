"""
Reconnaissance tools - Passive information gathering
Subdomain enumeration, technology detection, OSINT
"""
import asyncio
import aiohttp
import json
from typing import List, Dict, Any, Optional
from datetime import datetime


async def run_subdomain_enum(domain: str) -> Dict[str, Any]:
    """
    Run subdomain enumeration using multiple techniques
    
    Args:
        domain: Target domain
        
    Returns:
        Dictionary with discovered subdomains and metadata
    """
    result = {
        "domain": domain,
        "subdomains": [],
        "sources": [],
        "timestamp": datetime.utcnow().isoformat(),
        "status": "completed"
    }
    
    # Technique 1: Certificate Transparency logs (via crt.sh API)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    subdomains = set()
                    for entry in data:
                        name = entry.get('name_value', '')
                        for sub in name.split('\n'):
                            subdomains.add(sub.strip().lower())
                    
                    result['subdomains'].extend(list(subdomains))
                    result['sources'].append('crt.sh')
    except Exception as e:
        result['sources'].append(f'crt.sh failed: {str(e)}')
    
    # Technique 2: Common subdomain brute-forcing
    common_subs = [
        'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
        'api', 'app', 'web', 'portal', 'login', 'auth', 'sso'
    ]
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for sub in common_subs:
            target = f"{sub}.{domain}"
            tasks.append(check_subdomain(session, target))
        
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, res in enumerate(results):
                if isinstance(res, dict) and res.get('exists'):
                    result['subdomains'].append(res['subdomain'])
        except Exception:
            pass
    
    result['subdomains'] = list(set(result['subdomains']))
    result['count'] = len(result['subdomains'])
    
    return result


async def check_subdomain(session: aiohttp.ClientSession, subdomain: str) -> Dict[str, Any]:
    """Check if a subdomain resolves and responds"""
    try:
        async with session.get(
            f"http://{subdomain}",
            timeout=aiohttp.ClientTimeout(total=5),
            allow_redirects=False
        ) as response:
            return {
                "subdomain": subdomain,
                "exists": True,
                "status_code": response.status,
                "has_content": len(await response.text()) > 0
            }
    except Exception:
        return {"subdomain": subdomain, "exists": False}


async def run_tech_detection(domain: str) -> Dict[str, Any]:
    """
    Detect technologies used by the target
    
    Args:
        domain: Target domain
        
    Returns:
        Dictionary with detected technologies
    """
    result = {
        "domain": domain,
        "technologies": [],
        "headers": {},
        "server_info": {},
        "timestamp": datetime.utcnow().isoformat()
    }
    
    urls_to_check = [
        f"http://{domain}",
        f"https://{domain}"
    ]
    
    async with aiohttp.ClientSession() as session:
        for url in urls_to_check:
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True
                ) as response:
                    # Extract headers
                    result['headers'] = dict(response.headers)
                    
                    # Server info
                    server = response.headers.get('Server', '')
                    x_powered_by = response.headers.get('X-Powered-By', '')
                    
                    if server:
                        result['server_info']['server'] = server
                        result['technologies'].append({
                            "name": "Web Server",
                            "value": server,
                            "confidence": 80
                        })
                    
                    if x_powered_by:
                        result['server_info']['x_powered_by'] = x_powered_by
                        result['technologies'].append({
                            "name": "Framework/Language",
                            "value": x_powered_by,
                            "confidence": 90
                        })
                    
                    # Check body for tech signatures
                    body = await response.text()
                    tech_signatures = {
                        "WordPress": "wp-content",
                        "Drupal": "Drupal.settings",
                        "Joomla": "Joomla!",
                        "React": "react-root",
                        "Angular": "ng-app",
                        "Vue.js": "__vue__",
                        "jQuery": "jquery",
                        "Bootstrap": "bootstrap",
                        "Nginx": "nginx",
                        "Apache": "Apache"
                    }
                    
                    for tech, signature in tech_signatures.items():
                        if signature.lower() in body.lower():
                            result['technologies'].append({
                                "name": tech,
                                "value": signature,
                                "confidence": 70
                            })
                    
                    break  # Got successful response
                    
            except Exception as e:
                result['server_info']['error'] = str(e)
                continue
    
    result['technology_count'] = len(result['technologies'])
    
    return result


async def run_whois_lookup(domain: str) -> Dict[str, Any]:
    """
    Perform WHOIS lookup (simplified, uses public API)
    
    Args:
        domain: Target domain
        
    Returns:
        WHOIS information dictionary
    """
    result = {
        "domain": domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "nameservers": [],
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Note: Real WHOIS would use python-whois library
    # This is a placeholder for the actual implementation
    
    return result


async def run_dns_enumeration(domain: str) -> Dict[str, Any]:
    """
    Enumerate DNS records for a domain
    
    Args:
        domain: Target domain
        
    Returns:
        DNS records dictionary
    """
    result = {
        "domain": domain,
        "records": {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": []
        },
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Note: Real DNS enumeration would use dnspython library
    # This is a placeholder for the actual implementation
    
    return result
