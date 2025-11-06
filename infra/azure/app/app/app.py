from flask import Flask, request, Response, abort
import requests
import os

app = Flask(__name__)

# ------------------------------------------------------------------
# Configuration from environment
# ------------------------------------------------------------------
TARGET_BASE = os.getenv("ENCLAVE_REDIRECTOR", "").rstrip("/")

def parse_allowed(env_var: str):
    """Return a set of allowed paths, or None to allow all traffic."""
    value = os.getenv(env_var)
    if not value or value.lower() in {"none", "null", ""}:
        return None  # No restriction → allow all
    paths = {p.strip().lstrip("/") for p in value.split(",") if p.strip()}
    return paths or None

ALLOWED_GET  = parse_allowed("ALLOWED_GET_PATHS")
ALLOWED_POST = parse_allowed("ALLOWED_POST_PATHS")
    
if not TARGET_BASE.startswith(('http://', 'https://')):
    TARGET_BASE = 'https://' + TARGET_BASE

# ------------------------------------------------------------------
# Log config once after first request
# ------------------------------------------------------------------
_config_logged = False
@app.after_request
def log_config_once(response):
    global _config_logged
    if not _config_logged:
        app.logger.info(f"Proxy Target: {TARGET_BASE}")
        app.logger.info(f"Allowed GET paths: {ALLOWED_GET or 'ALL'}")
        app.logger.info(f"Allowed POST paths: {ALLOWED_POST or 'ALL'}")
        _config_logged = True
    return response

# ------------------------------------------------------------------
# Check if a request is allowed
# ------------------------------------------------------------------
def is_allowed(method: str, path: str) -> bool:
    clean = path.lstrip("/")
    if method == "GET":
        return True if not ALLOWED_GET else clean in ALLOWED_GET or clean == ""
    if method == "POST":
        return True if not ALLOWED_POST else clean in ALLOWED_POST or clean == ""
    return False

# ------------------------------------------------------------------
# Proxy logic
# ------------------------------------------------------------------
def proxy_request():
    if not TARGET_BASE:
        abort(500, "ENCLAVE_REDIRECTOR not set")
    if not is_allowed(request.method, request.path):
        app.logger.warning(f"Blocked: {request.method} {request.path}")
        abort(403)

    target_url = f"{TARGET_BASE}{request.full_path}" if request.query_string else f"{TARGET_BASE}{request.path}"

    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers={k: v for k, v in request.headers if k.lower() != "host"},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=True,
            timeout=30,
        )
    except Exception as e:
        app.logger.error(f"Upstream error: {e}")
        abort(502)

    excluded_headers = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    headers = [(k, v) for k, v in resp.raw.headers.items() if k.lower() not in excluded_headers]

    return Response(resp.iter_content(8192), resp.status_code, headers)

# ------------------------------------------------------------------
# Catch-all routes
# ------------------------------------------------------------------
@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def catch_all(path):
    return proxy_request()

# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
