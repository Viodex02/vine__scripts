# ===============================
# Vine GitScript – Real Scanner
# ===============================

from urllib.parse import urlparse, parse_qs
import re
import time

# -------------------------------
# Helpers
# -------------------------------

def now():
    return time.strftime("%H:%M:%S")

def info(msg):
    ctx.Println(f"[{now()}] [INFO] {msg}")

def warn(msg):
    ctx.Println(f"[{now()}] [WARN] {msg}")

def good(msg):
    ctx.Println(f"[{now()}] [OK] {msg}")

# -------------------------------
# URL Analysis
# -------------------------------

def analyze_url(url: str) -> dict:
    parsed = urlparse(url)

    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "path": parsed.path or "/",
        "query": parse_qs(parsed.query),
        "raw_query": parsed.query,
    }

# -------------------------------
# Header Checks
# -------------------------------

def check_security_headers(headers):
    findings = []

    required = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]

    for h in required:
        if h not in headers:
            findings.append(f"Missing security header: {h}")

    return findings

# -------------------------------
# Response Content Checks
# -------------------------------

def keyword_scan(text: str):
    hits = []

    patterns = {
        "debug": r"(debug|stack trace|exception)",
        "sql": r"(sql syntax|mysql|psql|sqlite)",
        "internal": r"(internal server|traceback)",
    }

    for name, regex in patterns.items():
        if re.search(regex, text, re.I):
            hits.append(name)

    return hits

# -------------------------------
# Main Entry
# -------------------------------

async def run(ctx):
    info("GitScript started")

    # ---------------------------
    # URL
    # ---------------------------
    url_data = analyze_url(ctx.url)

    info(f"Target: {url_data['host']}")
    info(f"Scheme: {url_data['scheme']}")
    info(f"Port: {url_data['port']}")
    info(f"Path: {url_data['path']}")

    if url_data["query"]:
        warn(f"Query params detected: {list(url_data['query'].keys())}")
    else:
        info("No query parameters")

    # ---------------------------
    # Response
    # ---------------------------
    res = ctx.response

    info(f"Status Code: {res.status_code}")

    if res.status_code >= 500:
        warn("Server error detected")
    elif res.status_code == 403:
        warn("Forbidden response")
    elif res.status_code == 200:
        good("Target is alive")

    # ---------------------------
    # Headers
    # ---------------------------
    header_issues = check_security_headers(res.headers)

    if header_issues:
        warn("Security header issues found:")
        for h in header_issues:
            warn(f" - {h}")
    else:
        good("All important security headers present")

    # ---------------------------
    # Body Analysis
    # ---------------------------
    body = res.text or ""

    if len(body) == 0:
        warn("Empty response body")
    else:
        info(f"Response size: {len(body)} bytes")

    keyword_hits = keyword_scan(body)

    if keyword_hits:
        warn("Sensitive keywords found in response:")
        for k in keyword_hits:
            warn(f" - {k}")
    else:
        good("No sensitive keywords detected")

    # ---------------------------
    # Final
    # ---------------------------
    info("GitScript finished cleanly")
