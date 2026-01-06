from urllib.parse import urlparse, parse_qs
import time
import re

class VineCTX:
    def __init__(self, url, response):
        self.url = url
        self.response = response

    # ------------------
    # Logging
    # ------------------
    def now(self):
        return time.strftime("%H:%M:%S")

    def info(self, msg):
        print(f"[{self.now()}] [INFO] {msg}")

    def warn(self, msg):
        print(f"[{self.now()}] [WARN] {msg}")

    def good(self, msg):
        print(f"[{self.now()}] [OK] {msg}")

    # ------------------
    # URL helpers
    # ------------------
    def parse_url(self):
        parsed = urlparse(self.url)

        return {
            "scheme": parsed.scheme,
            "host": parsed.hostname,
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "path": parsed.path or "/",
            "query": parse_qs(parsed.query),
            "raw_query": parsed.query,
        }

    # ------------------
    # Response helpers
    # ------------------
    def status(self):
        return self.response.status_code

    def headers(self):
        return self.response.headers

    def body(self):
        return self.response.text or ""

    # ------------------
    # Scanning helpers
    # ------------------
    def check_headers(self, required):
        missing = []
        for h in required:
            if h not in self.response.headers:
                missing.append(h)
        return missing

    def keyword_scan(self, patterns: dict):
        hits = []
        body = self.body()

        for name, regex in patterns.items():
            if re.search(regex, body, re.I):
                hits.append(name)

        return hits
