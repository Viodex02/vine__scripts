# ==========================================
# Vine GitScript - Full Logic Scanner
# ==========================================

import re
from urllib.parse import urlparse

async def run(ctx):
    """
    Vine GitScript Entry Point
    ctx.url       -> string URL
    ctx.response  -> http response object
    """

    findings = []

    def log(msg):
        ctx.Println(msg)

    def add_finding(name, severity, desc):
        findings.append({
            "name": name,
            "severity": severity,
            "description": desc,
            "url": ctx.url
        })

    # -----------------------------
    # URL Parsing
    # -----------------------------

    parsed = urlparse(ctx.url)

    scheme = parsed.scheme
    host = parsed.hostname
    port = parsed.port
    path = parsed.path or "/"
    query = parsed.query

    log(f"Scanning: {scheme}://{host}{path}")

    if scheme != "https":
        add_finding(
            "Insecure Scheme",
            "low",
            "Target is not using HTTPS"
        )

    if port and port not in (80, 443):
        add_finding(
            "Non Standard Port",
            "info",
            f"Port {port} detected"
        )

    # -----------------------------
    # Response Checks
    # -----------------------------

    if ctx.response is None:
        log("No response object")
        return

    status = ctx.response.status_code
    headers = ctx.response.headers
    body = ctx.response.text or ""
    body_lower = body.lower()

    log(f"Status Code: {status}")

    # -----------------------------
    # Status Logic
    # -----------------------------

    if status >= 500:
        add_finding(
            "Server Error",
            "high",
            f"Server returned {status}"
        )

    if status in (401, 403):
        add_finding(
            "Protected Resource",
            "medium",
            f"Received {status}"
        )

    # -----------------------------
    # Header Analysis
    # -----------------------------

    if "server" in headers:
        add_finding(
            "Server Disclosure",
            "low",
            headers.get("server")
        )

    if "x-powered-by" in headers:
        add_finding(
            "Technology Disclosure",
            "low",
            headers.get("x-powered-by")
        )

    # -----------------------------
    # Security Headers
    # -----------------------------

    security_headers = [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "strict-transport-security",
        "referrer-policy"
    ]

    missing = []
    for h in security_headers:
        if h not in headers:
            missing.append(h)

    if missing:
        add_finding(
            "Missing Security Headers",
            "medium",
            ", ".join(missing)
        )

    # -----------------------------
    # Sensitive Keywords
    # -----------------------------

    keywords = [
        "password",
        "passwd",
        "secret",
        "apikey",
        "api_key",
        "token",
        "authorization",
        "private_key"
    ]

    for kw in keywords:
        if kw in body_lower:
            add_finding(
                "Sensitive Keyword",
                "high",
                f"Keyword '{kw}' found"
            )

    # -----------------------------
    # Error Disclosure
    # -----------------------------

    error_signatures = [
        "traceback",
        "stack trace",
        "fatal error",
        "exception",
        "warning:"
    ]

    for err in error_signatures:
        if err in body_lower:
            add_finding(
                "Error Disclosure",
                "high",
                err
            )

    # -----------------------------
    # JS Discovery (basic)
    # -----------------------------

    js_files = re.findall(r'src=["\'](.*?\.js)["\']', body, re.I)
    if js_files:
        add_finding(
            "JavaScript Files",
            "info",
            js_files[:10]
        )

    # -----------------------------
    # Output
    # -----------------------------

    log(f"Findings count: {len(findings)}")
    for f in findings:
        log(f"[{f['severity']}] {f['name']} -> {f['description']}")
