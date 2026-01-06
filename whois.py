from urllib.parse import urlparse, parse_qs
import re
import time

async def run(ctx):
    # -----------------------------
    # Local helpers (INSIDE run)
    # -----------------------------
    def log(level, msg):
        now = time.strftime("%H:%M:%S")
        ctx.Println(f"[{now}] [{level}] {msg}")

    # -----------------------------
    # URL Analysis
    # -----------------------------
    parsed = urlparse(ctx.url)

    scheme = parsed.scheme
    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    query = parse_qs(parsed.query)

    log("INFO", f"Target: {host}")
    log("INFO", f"Scheme: {scheme}")
    log("INFO", f"Port: {port}")
    log("INFO", f"Path: {path}")

    if query:
        log("WARN", f"Query params: {list(query.keys())}")
    else:
        log("INFO", "No query parameters")

    # -----------------------------
    # Response Analysis
    # -----------------------------
    res = ctx.response

    if not res:
        log("ERROR", "No response object")
        return

    log("INFO", f"Status Code: {res.status_code}")

    if res.status_code >= 500:
        log("WARN", "Server error detected")
    elif res.status_code == 403:
        log("WARN", "Forbidden response")
    elif res.status_code == 200:
        log("OK", "Target is alive")

    # -----------------------------
    # Headers Check
    # -----------------------------
    headers = res.headers

    security_headers = [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "strict-transport-security",
        "referrer-policy",
    ]

    missing = []
    for h in security_headers:
        if h not in headers:
            missing.append(h)

    if missing:
        log("WARN", f"Missing security headers: {', '.join(missing)}")
    else:
        log("OK", "All important security headers present")

    # -----------------------------
    # Body Scan
    # -----------------------------
    body = res.text or ""
    body_lower = body.lower()

    log("INFO", f"Response size: {len(body)} bytes")

    keywords = [
        "password",
        "secret",
        "apikey",
        "token",
        "traceback",
        "exception",
        "stack trace",
    ]

    found = []
    for kw in keywords:
        if kw in body_lower:
            found.append(kw)

    if found:
        for k in found:
            log("WARN", f"Sensitive keyword found: {k}")
    else:
        log("OK", "No sensitive keywords detected")

    # -----------------------------
    # JS Discovery
    # -----------------------------
    js_files = re.findall(r'src=["\'](.*?\.js)["\']', body, re.I)
    if js_files:
        log("INFO", f"JavaScript files found ({len(js_files)}):")
        for js in js_files[:5]:
            log("INFO", f" - {js}")

    log("INFO", "GitScript finished cleanly")
