"""
Security scanners - Active enumeration and vulnerability scanning
Port scanning, web vulnerability detection, service enumeration
"""
import asyncio
import aiohttp
import socket
from typing import List, Dict, Any, Optional
from datetime import datetime


async def run_port_scan(target: str, ports: List[int] = None) -> Dict[str, Any]:
    """
    Run TCP port scan on target
    
    Args:
        target: Target domain or IP
        ports: List of ports to scan (default: common ports)
        
    Returns:
        Dictionary with open ports and service info
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                 3306, 3389, 5432, 5900, 8080, 8443]
    
    result = {
        "target": target,
        "open_ports": [],
        "closed_ports": [],
        "filtered_ports": [],
        "scan_time": datetime.utcnow().isoformat(),
        "ports_scanned": len(ports)
    }
    
    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(target)
        result["ip_address"] = ip
    except socket.gaierror:
        result["error"] = f"Could not resolve {target}"
        return result
    
    # Scan ports asynchronously
    async def check_port(port: int) -> Dict[str, Any]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            
            # Try to identify service
            service = await identify_service(ip, port)
            
            return {
                "port": port,
                "state": "open",
                "service": service
            }
        except asyncio.TimeoutError:
            return {"port": port, "state": "filtered"}
        except ConnectionRefusedError:
            return {"port": port, "state": "closed"}
        except Exception:
            return {"port": port, "state": "filtered"}
    
    tasks = [check_port(port) for port in ports]
    results = await asyncio.gather(*tasks)
    
    for res in results:
        if res["state"] == "open":
            result["open_ports"].append(res)
        elif res["state"] == "closed":
            result["closed_ports"].append(res["port"])
        else:
            result["filtered_ports"].append(res["port"])
    
    result["open_count"] = len(result["open_ports"])
    
    return result


async def identify_service(ip: str, port: int) -> str:
    """Try to identify the service running on a port"""
    service_map = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }
    
    return service_map.get(port, "unknown")


async def run_web_scan(target: str, ports: List[int] = None) -> Dict[str, Any]:
    """
    Run web application security scan
    
    Args:
        target: Target domain
        ports: Ports to scan for HTTP/HTTPS (default: 80, 443)
        
    Returns:
        Dictionary with web vulnerabilities and findings
    """
    if ports is None:
        ports = [80, 443, 8080, 8443]
    
    result = {
        "target": target,
        "endpoints": [],
        "vulnerabilities": [],
        "security_headers": {},
        "timestamp": datetime.utcnow().isoformat()
    }
    
    endpoints_to_check = [
        "/", "/admin", "/login", "/api", "/robots.txt",
        "/sitemap.xml", "/.git", "/.env", "/wp-admin",
        "/phpinfo.php", "/test.php", "/backup"
    ]
    
    async with aiohttp.ClientSession() as session:
        for port in ports:
            for scheme in ["http", "https"]:
                base_url = f"{scheme}://{target}:{port}" if port not in [80, 443] else f"{scheme}://{target}"
                
                for endpoint in endpoints_to_check:
                    url = f"{base_url}{endpoint}"
                    try:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=5),
                            allow_redirects=True
                        ) as response:
                            finding = {
                                "url": url,
                                "status_code": response.status,
                                "content_length": len(await response.text()),
                                "headers": dict(response.headers)
                            }
                            
                            # Check for sensitive files
                            if response.status == 200:
                                if endpoint in ["/.git", "/.env", "/phpinfo.php"]:
                                    finding["severity"] = "high"
                                    finding["type"] = "sensitive_file_exposed"
                                    result["vulnerabilities"].append(finding)
                                elif endpoint == "/admin" and response.status == 200:
                                    finding["severity"] = "medium"
                                    finding["type"] = "admin_panel_exposed"
                                    result["vulnerabilities"].append(finding)
                            
                            # Check security headers
                            if endpoint == "/":
                                result["security_headers"][f"{scheme}:{port}"] = {
                                    "x_frame_options": response.headers.get("X-Frame-Options"),
                                    "x_content_type_options": response.headers.get("X-Content-Type-Options"),
                                    "strict_transport_security": response.headers.get("Strict-Transport-Security"),
                                    "content_security_policy": response.headers.get("Content-Security-Policy")
                                }
                            
                            result["endpoints"].append(finding)
                            
                    except Exception:
                        continue
    
    # Analyze security headers
    for proto_port, headers in result["security_headers"].items():
        missing = []
        if not headers.get("x_frame_options"):
            missing.append("X-Frame-Options")
        if not headers.get("x_content_type_options"):
            missing.append("X-Content-Type-Options")
        if not headers.get("strict_transport_security"):
            missing.append("Strict-Transport-Security")
        if not headers.get("content_security_policy"):
            missing.append("Content-Security-Policy")
        
        if missing:
            result["vulnerabilities"].append({
                "type": "missing_security_headers",
                "severity": "low",
                "missing_headers": missing,
                "protocol": proto_port
            })
    
    result["vulnerability_count"] = len(result["vulnerabilities"])
    result["endpoint_count"] = len(result["endpoints"])
    
    return result


async def run_directory_bruteforce(target: str, wordlist: List[str] = None) -> Dict[str, Any]:
    """
    Bruteforce directories and files on web server
    
    Args:
        target: Target domain
        wordlist: List of paths to check
        
    Returns:
        Dictionary with discovered paths
    """
    if wordlist is None:
        wordlist = [
            "admin", "backup", "config", "database", "db",
            "files", "images", "includes", "uploads", "tmp",
            "test", "dev", "staging", "api", "docs"
        ]
    
    result = {
        "target": target,
        "found_paths": [],
        "checked_count": 0,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    async with aiohttp.ClientSession() as session:
        for path in wordlist:
            for scheme in ["http", "https"]:
                url = f"{scheme}://{target}/{path}"
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=3),
                        allow_redirects=True
                    ) as response:
                        result["checked_count"] += 1
                        
                        if response.status in [200, 301, 302, 403]:
                            result["found_paths"].append({
                                "path": path,
                                "url": url,
                                "status": response.status,
                                "redirect_location": response.headers.get("Location")
                            })
                except Exception:
                    continue
    
    result["found_count"] = len(result["found_paths"])
    
    return result
