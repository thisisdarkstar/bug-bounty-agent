"""
Local LLM Integration via LM Studio
OpenAI-compatible API wrapper with async support, caching, and concurrency control
"""
import asyncio
import hashlib
import json
import time
from typing import Optional, List, Dict, Any, Callable
from pathlib import Path
from datetime import datetime

import httpx
from openai import AsyncOpenAI


class LLMCache:
    """Cache for LLM responses to reduce redundant calls"""
    
    def __init__(self, cache_dir: str = None, ttl: int = 3600):
        if cache_dir is None:
            # Use relative path from project root
            project_root = Path(__file__).parent.parent
            cache_dir = str(project_root / "data" / "llm_cache")
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl
        self._memory_cache: Dict[str, Dict] = {}
    
    def _get_cache_key(self, prompt: str, model: str, temperature: float) -> str:
        """Generate cache key from prompt parameters"""
        content = f"{prompt}|{model}|{temperature}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def get(self, key: str) -> Optional[str]:
        """Get cached response if available and not expired"""
        # Check memory cache first
        if key in self._memory_cache:
            entry = self._memory_cache[key]
            if time.time() - entry["timestamp"] < self.ttl:
                return entry["content"]
            else:
                del self._memory_cache[key]
        
        # Check disk cache
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    entry = json.load(f)
                    if time.time() - entry["timestamp"] < self.ttl:
                        self._memory_cache[key] = entry
                        return entry["content"]
                    else:
                        cache_file.unlink()
            except Exception:
                pass
        return None
    
    def set(self, key: str, content: str):
        """Cache a response"""
        entry = {
            "content": content,
            "timestamp": time.time()
        }
        self._memory_cache[key] = entry
        
        # Write to disk
        cache_file = self.cache_dir / f"{key}.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump(entry, f)
        except Exception:
            pass


class LLMClient:
    """Async LLM client for LM Studio integration"""
    
    def __init__(
        self,
        endpoint: str = "http://localhost:1234/v1",
        model: str = "Dolphin-2.9.2-Llama3-8B",
        max_tokens: int = 4096,
        timeout: int = 30,
        retry_attempts: int = 3,
        concurrency_limit: int = 2,
        temperature: float = 0.1,
        cache_enabled: bool = True
    ):
        self.endpoint = endpoint.rstrip('/')
        self.model = model
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        self.temperature = temperature
        self.cache = LLMCache() if cache_enabled else None
        
        # Initialize OpenAI client with custom base URL
        self.client = AsyncOpenAI(
            base_url=f"{self.endpoint}",
            api_key="not-needed"  # LM Studio doesn't require auth
        )
        
        # Concurrency control
        self._semaphore = asyncio.Semaphore(concurrency_limit)
        self._request_count = 0
        self._total_latency = 0.0
        
    async def _execute_with_retry(
        self, 
        func: Callable, 
        *args, 
        **kwargs
    ) -> Any:
        """Execute function with exponential backoff retry"""
        last_exception = None
        
        for attempt in range(self.retry_attempts):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if attempt < self.retry_attempts - 1:
                    wait_time = (2 ** attempt) * 0.5  # Exponential backoff
                    await asyncio.sleep(wait_time)
        
        raise last_exception
    
    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        force_json: bool = False
    ) -> str:
        """
        Get chat completion from LLM
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            system_prompt: Optional system prompt to prepend
            temperature: Override default temperature
            max_tokens: Override default max tokens
            force_json: Try to enforce JSON output via prompt
            
        Returns:
            Response content string
        """
        async with self._semaphore:
            # Prepare messages
            final_messages = []
            if system_prompt:
                final_messages.append({"role": "system", "content": system_prompt})
            final_messages.extend(messages)
            
            # Add JSON enforcement if requested
            if force_json:
                json_instruction = "\n\nIMPORTANT: Respond ONLY with valid JSON. No markdown, no explanations."
                final_messages[-1]["content"] += json_instruction
            
            # Check cache
            cache_key = None
            if self.cache:
                prompt_str = json.dumps(final_messages, sort_keys=True)
                cache_key = self.cache._get_cache_key(
                    prompt_str, 
                    self.model, 
                    temperature or self.temperature
                )
                cached_response = self.cache.get(cache_key)
                if cached_response:
                    return cached_response
            
            # Execute with retry
            start_time = time.time()
            response = await self._execute_with_retry(
                self.client.chat.completions.create,
                model=self.model,
                messages=final_messages,
                temperature=temperature or self.temperature,
                max_tokens=max_tokens or self.max_tokens,
                top_p=0.95,
            )
            latency = time.time() - start_time
            
            # Update metrics
            self._request_count += 1
            self._total_latency += latency
            
            content = response.choices[0].message.content.strip()
            
            # Cache response
            if self.cache and cache_key:
                self.cache.set(cache_key, content)
            
            return content
    
    async def analyze_tool_output(
        self,
        tool_name: str,
        output: str,
        task_type: str = "recon"
    ) -> Dict[str, Any]:
        """
        Analyze tool output using LLM
        
        Args:
            tool_name: Name of the tool that produced the output
            output: Raw tool output
            task_type: Type of analysis (recon, enumeration, validation)
            
        Returns:
            Structured analysis results
        """
        system_prompts = {
            "recon": """You are a security reconnaissance assistant. Analyze the following tool output and extract relevant information about the target's infrastructure, technologies, and potential attack surface. Be concise and structured.

Respond with JSON in this format:
{
    "technologies": ["list", "of", "detected", "technologies"],
    "endpoints": ["/list", "/of", "/endpoints"],
    "subdomains": ["sub1.example.com"],
    "interesting_findings": ["finding1", "finding2"],
    "recommendations": ["next steps"]
}""",
            
            "enumeration": """You are a vulnerability enumeration assistant. Analyze scan results and identify potential vulnerabilities, misconfigurations, or interesting endpoints. Focus on actionable findings with clear evidence.

Respond with JSON in this format:
{
    "potential_vulnerabilities": [
        {
            "title": "Vulnerability name",
            "description": "Brief description",
            "evidence": "Specific evidence from output",
            "severity": "low|medium|high|critical",
            "confidence": 0-100
        }
    ],
    "recommended_validations": ["validation steps"]
}""",
            
            "validation": """You are a vulnerability validation expert. Review the potential vulnerability and determine if it's a true positive. Provide confidence score, severity assessment, and proof-of-concept steps if applicable.

Respond with JSON in this format:
{
    "is_valid": true/false,
    "confidence_score": 0-100,
    "severity": "low|medium|high|critical",
    "cwe_ids": ["CWE-XXX"],
    "cvss_estimate": 0.0-10.0,
    "proof_of_concept": "Steps to reproduce",
    "remediation": "How to fix",
    "false_positive_indicators": ["reasons if FP"]
}"""
        }
        
        system_prompt = system_prompts.get(task_type, system_prompts["enumeration"])
        
        user_message = f"""Tool: {tool_name}

Output:
{output}

Analyze this output according to your role."""
        
        response = await self.chat_completion(
            messages=[{"role": "user", "content": user_message}],
            system_prompt=system_prompt,
            force_json=True
        )
        
        # Parse JSON response
        try:
            # Clean up markdown code blocks if present
            response = response.replace("```json", "").replace("```", "").strip()
            return json.loads(response)
        except json.JSONDecodeError:
            return {"error": "Failed to parse LLM response", "raw": response}
    
    async def generate_report_section(
        self,
        section_type: str,
        findings: List[Dict[str, Any]],
        target: str
    ) -> str:
        """Generate a report section from findings"""
        
        system_prompt = """You are a security report writer. Transform technical findings into clear, professional reports suitable for both technical teams and executives. Include remediation steps and business impact.

Write in a professional, objective tone. Use markdown formatting for structure."""
        
        findings_text = "\n\n".join([
            f"### {f['title']}\nSeverity: {f['severity'].upper()}\nDescription: {f['description']}\nEvidence: {f.get('proof_of_concept', 'N/A')}\nRemediation: {f.get('remediation', 'N/A')}"
            for f in findings
        ])
        
        user_message = f"""Generate a {section_type} section for a security assessment report.

Target: {target}

Findings:
{findings_text}

Include executive summary, risk assessment, and prioritized recommendations."""
        
        return await self.chat_completion(
            messages=[{"role": "user", "content": user_message}],
            system_prompt=system_prompt
        )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get LLM client metrics"""
        avg_latency = (
            self._total_latency / self._request_count 
            if self._request_count > 0 else 0
        )
        return {
            "total_requests": self._request_count,
            "average_latency_ms": avg_latency * 1000,
            "cache_enabled": self.cache is not None,
            "model": self.model,
            "endpoint": self.endpoint
        }


# Global LLM client instance
llm_client = LLMClient()
