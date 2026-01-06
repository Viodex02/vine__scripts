import asyncio
import httpx
import re
import json
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

# ==========================================================
# Context Object
# ==========================================================

@dataclass
class ScanContext:
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    response: Optional[httpx.Response] = None
    start_time: float = field(default_factory=time.time)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, name: str, severity: str, description: str, evidence: Any = None):
        self.findings.append({
            "name": name,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "url": self.url
        })

# ==========================================================
# Base Check Class
# ==========================================================

class BaseCheck:
    name = "BaseCheck"
    severity = "info"

    async def run(self, ctx: ScanContext):
        raise NotImplementedError

# ==========================================================
# Checks Implementations
# ==========================================================

class GoogleDetectionCheck(BaseCheck):
    name = "Google Detection"
    severity = "info"

    async def run(self, ctx: ScanContext):
        if ctx.url == "https://google.com":
            ctx.add_finding(
                self.name,
                self.severity,
                "Target is exactly google.com",
                ctx.url
            )

        if ctx.response and "google" in ctx.response.text.lower():
            ctx.add_finding(
                self.name,
                self.severity,
                "Keyword 'google' found in response body"
            )

class StatusCodeCheck(BaseCheck):
    name = "Status Code Analyzer"
    severity = "info"

    async def run(self, ctx: ScanContext):
        if not ctx.response:
            return

        code = ctx.response.status_code

        if code >= 500:
            ctx.add_finding(
                self.name,
                "high",
                f"Server error detected ({code})"
            )
        elif code == 403:
            ctx.add_finding(
                self.name,
                "medium",
                "403 Forbidden may indicate protected resource"
            )
        elif code == 401:
            ctx.add_finding(
                self.name,
                "medium",
                "401 Unauthorized endpoint detected"
            )

class ServerHeaderLeakCheck(BaseCheck):
    name = "Server Header Leak"
    severity = "low"

    async def run(self, ctx: ScanContext):
        if not ctx.response:
            return

        server = ctx.response.headers.get("Server")
        powered = ctx.response.headers.get("X-Powered-By")

        if server:
            ctx.add_finding(
                self.name,
                "low",
                "Server header disclosed",
                server
            )

        if powered:
            ctx.add_finding(
                self.name,
                "low",
                "X-Powered-By header disclosed",
                powered
            )

class SecurityHeadersCheck(BaseCheck):
    name = "Security Headers"
    severity = "medium"

    REQUIRED_HEADERS = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy"
    ]

    async def run(self, ctx: ScanContext):
        if not ctx.response:
            return

        missing = []

        for h in self.REQUIRED_HEADERS:
            if h not in ctx.response.headers:
                missing.append(h)

        if missing:
            ctx.add_finding(
                self.name,
                "medium",
                "Missing security headers",
                missing
            )

class SensitiveKeywordCheck(BaseCheck):
    name = "Sensitive Keywords"
    severity = "high"

    KEYWORDS = [
        "password",
        "secret",
        "api_key",
        "apikey",
        "token",
        "authorization",
        "aws_access_key"
    ]

    async def run(self, ctx: ScanContext):
        if not ctx.response:
            return

        body = ctx.response.text.lower()

        for kw in self.KEYWORDS:
            if kw in body:
                ctx.add_finding(
                    self.name,
                    "high",
                    f"Sensitive keyword found: {kw}"
                )

class RegexPatternCheck(BaseCheck):
    name = "Regex Pattern Scanner"
    severity = "medium"

    PATTERNS = {
        "JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "IP Address": r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
    }

    async def run(self, ctx: ScanContext):
        if not ctx.response:
            return

        for name, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, ctx.response.text)
            if matches:
                ctx.add_finding(
                    self.name,
                    "medium",
                    f"{name} pattern found",
                    matches[:5]
                )

class JavaScriptEndpointDiscovery(BaseCheck):
    name = "JS Endpoint Discovery"
    severity = "low"

    async def run(self, ctx: ScanContext):
        if not ctx.response:
            return

        js_urls = re.findall(r'src=["\'](.*?\.js)["\']', ctx.response.text)

        full_urls = []
        for js in js_urls:
            full_urls.append(urljoin(ctx.url, js))

        if full_urls:
            ctx.add_finding(
                self.name,
                "low",
                "JavaScript files discovered",
                full_urls
            )

class SimpleWAFDetection(BaseCheck):
    name = "WAF Detection"
    severity = "info"

    async def run(self, ctx: ScanContext):
        if not ctx.response:
            return

        headers = ctx.response.headers

        waf_signatures = [
            "cloudflare",
            "akamai",
            "sucuri",
            "imperva"
        ]

        for sig in waf_signatures:
            for value in headers.values():
                if sig in value.lower():
                    ctx.add_finding(
                        self.name,
                        "info",
                        f"Possible WAF detected: {sig}"
                    )
                    return

# ==========================================================
# Scanner Engine
# ==========================================================

class AsyncScanner:
    def __init__(self, timeout: int = 10):
        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True
        )
        self.checks: List[BaseCheck] = []

    def register_check(self, check: BaseCheck):
        self.checks.append(check)

    async def fetch(self, ctx: ScanContext):
        try:
            ctx.response = await self.client.request(
                ctx.method,
                ctx.url,
                headers=ctx.headers
            )
        except Exception as e:
            ctx.add_finding(
                "Request Error",
                "high",
                "Failed to fetch URL",
                str(e)
            )

    async def run_checks(self, ctx: ScanContext):
        for check in self.checks:
            try:
                await check.run(ctx)
            except Exception as e:
                ctx.add_finding(
                    "Check Error",
                    "low",
                    f"Check {check.name} failed",
                    str(e)
                )

    async def scan(self, url: str) -> ScanContext:
        ctx = ScanContext(url=url)

        await self.fetch(ctx)
        await self.run_checks(ctx)

        return ctx

    async def close(self):
        await self.client.aclose()

# ==========================================================
# Entry Point
# ==========================================================

async def run(ctx_url: str):
    scanner = AsyncScanner()

    # Register checks
    scanner.register_check(GoogleDetectionCheck())
    scanner.register_check(StatusCodeCheck())
    scanner.register_check(ServerHeaderLeakCheck())
    scanner.register_check(SecurityHeadersCheck())
    scanner.register_check(SensitiveKeywordCheck())
    scanner.register_check(RegexPatternCheck())
    scanner.register_check(JavaScriptEndpointDiscovery())
    scanner.register_check(SimpleWAFDetection())

    ctx = await scanner.scan(ctx_url)

    print("\n========== Scan Results ==========")
    print(json.dumps(ctx.findings, indent=2))

    await scanner.close()

# ==========================================================
# CLI Execution
# ==========================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python scanner.py <url>")
        sys.exit(1)

    asyncio.run(run(sys.argv[1]))
