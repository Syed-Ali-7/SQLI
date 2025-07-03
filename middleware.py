import re
import json
import datetime
from flask import Response
from io import BytesIO
from urllib.parse import unquote

BLOCKED_IPS_FILE = "logs/blocked_ips.log"

# EXTENSIVE SQL INJECTION PATTERNS
SQLI_PATTERNS = [
    # Logical operators and tautologies
    r"(?i)\bOR\s+1=1\b", r"(?i)\bAND\s+1=1\b", r"(?i)'?\s*OR\s*'1'\s*=\s*'1'", r"(?i)\"?\s*OR\s*\"1\"\s*=\s*\"1\"",

    # Classic UNION attacks
    r"(?i)\bUNION\b.*\bSELECT\b", r"(?i)\bSELECT\b.*\bFROM\b", r"(?i)\bINSERT\b\s+INTO\b", r"(?i)\bDELETE\s+FROM\b",
    r"(?i)\bUPDATE\s+\w+\s+SET\b", r"(?i)\bDROP\s+TABLE\b", r"(?i)\bTRUNCATE\b", r"(?i)\bALTER\s+TABLE\b",

    # Stacked queries
    r";\s*DROP\b", r";\s*INSERT\b", r";\s*UPDATE\b", r";\s*DELETE\b",

    # Comments
    r"--", r"#", r"/\*.*?\*/",

    # Sleep/time-based injections
    r"(?i)\bSLEEP\s*\(", r"(?i)\bWAITFOR\s+DELAY\b", r"(?i)\bBENCHMARK\s*\(",

    # Hex, binary, casting
    r"(?i)0x[0-9a-fA-F]+", r"(?i)CHAR\s*\(", r"(?i)CAST\s*\(",

    # Information schema enumeration
    r"(?i)\bINFORMATION_SCHEMA\b", r"(?i)\bTABLE_SCHEMA\b", r"(?i)\bTABLE_NAME\b", r"(?i)\bCOLUMN_NAME\b",

    # Blind injection techniques
    r"(?i)' AND \d=\d --", r"(?i)\" AND \d=\d --",

    # Encoded attempts
    r"%27", r"%22", r"%3D", r"%2D%2D", r"%3B",

    # Common payload fragments
    r"(?i)\bexec\b", r"(?i)\bsp_executesql\b", r"(?i)\bxp_cmdshell\b", r"(?i)\bshutdown\b"
]

def detect_sqli(value):
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, value):
            return True
    return False

def log_sqli(ip, method, url, payloads):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] BLOCKED IP: {ip} | METHOD: {method} | URL: {url} | PAYLOADS: {payloads}"

    with open("logs/sqli_detected.log", "a") as f:
        f.write(log_message + "\n")

    # Block the IP
    with open(BLOCKED_IPS_FILE, "a+") as f:
        f.seek(0)
        blocked_ips = f.read().splitlines()
        if ip not in blocked_ips:
            f.write(ip + "\n")

class middleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        from werkzeug.wrappers import Request

        req = Request(environ)
        ip = req.remote_addr
        url = req.url
        method = req.method
        suspicious = False
        payloads = []

        try:
            with open(BLOCKED_IPS_FILE, "r") as f:
                blocked_ips = f.read().splitlines()
                if ip in blocked_ips:
                    return self._deny_request(req)
        except FileNotFoundError:
            pass

        # Query string detection
        query_string = unquote(req.query_string.decode())
        if detect_sqli(query_string):
            suspicious = True
            payloads.append(f"Query: {query_string}")

        # POST data
        if method == "POST":
            content_type = req.headers.get("Content-Type", "")
            if "application/json" in content_type:
                try:
                    json_data = json.loads(req.get_data())
                    for key, value in json_data.items():
                        if detect_sqli(str(value)):
                            suspicious = True
                            payloads.append(f"JSON {key}={value}")
                except:
                    pass
            elif "application/x-www-form-urlencoded" in content_type:
                try:
                    form_data = req.form
                    for key, value in form_data.items():
                        if detect_sqli(str(value)):
                            suspicious = True
                            payloads.append(f"Form {key}={value}")
                except:
                    pass

        if suspicious:
            log_sqli(ip, method, url, payloads)
            return self._deny_request(req)

        return self.app(environ, start_response)

    def _deny_request(self, req):
        if "text/html" in req.headers.get("Accept", ""):
            html = """
            <html>
            <head><title>403 Forbidden</title></head>
            <body>
                <h2>🚫 Access Denied</h2>
                <p>Your request was blocked due to suspicious SQL-like input.</p>
                <p>If this is an error, please contact the administrator.</p>
            </body>
            </html>
            """
            return Response(html, status=403, content_type="text/html")

        return Response(
            json.dumps({
                "error": "Access denied",
                "reason": "Suspicious SQL input detected",
                "status": 403
            }),
            status=403,
            content_type="application/json"
        )
