# app.py
from flask import Flask, request, Response, render_template, jsonify
import requests
import json
import datetime
from rules import check_request
import db
import os
from rate_limiter import SlidingWindowRateLimiter

# Rate limiting configuration
MAX_REQUESTS = 20        # max requests per window per IP
WINDOW_SECONDS = 10      # sliding window length in seconds

app = Flask(__name__)
db.init_db()

rate_limiter = SlidingWindowRateLimiter(MAX_REQUESTS, WINDOW_SECONDS)


def get_timestamp():
    """Return a human-readable timestamp string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_client_ip():
    """
    Extract the client IP address, handling cases where the app is behind
    a reverse proxy (e.g., Render) that sets the X-Forwarded-For header.
    """
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        # X-Forwarded-For may contain multiple IPs; take the first one
        client_ip = xff.split(',')[0].strip()
    else:
        client_ip = request.remote_addr or 'unknown'
    return client_ip

# ----------------------------------------------------------------------
# Dashboard and API routes (exempt from WAF rule checking)
# ----------------------------------------------------------------------
@app.route('/dashboard')
def dashboard():
    """Render the WAF monitoring dashboard."""
    return render_template('dashboard.html')


@app.route('/api/stats')
def api_stats():
    """Return aggregated statistics as JSON."""
    return jsonify(db.get_stats())


@app.route('/api/logs')
def api_logs():
    """Return recent logs as JSON (limit parameter, default 20)."""
    limit = request.args.get('limit', default=20, type=int)
    return jsonify(db.get_recent_logs(limit=limit))

# Catch-all route that captures any path, including the root "/".
# Methods allowed: GET, POST, PUT, DELETE (as required).

@app.route('/', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(subpath):
    # ---------- 1. Extract incoming request data ----------
    method = request.method
    full_url = request.url
    path = request.path
    query_params = request.args.to_dict(flat=False)
    headers = dict(request.headers)
    cookies = request.cookies.to_dict()
    client_ip = get_client_ip()
    raw_body = request.get_data()

    # parse json, form data, etc. (as before)
    ...

    # ---------- 2. Rate limiting check (BEFORE rule checking) ----------
    timestamp = get_timestamp()   # for logging in both branches

    if rate_limiter.is_rate_limited(client_ip):
        # Rate limit exceeded – block immediately
        print(f"[{timestamp}] IP={client_ip} path={path} "
              f"attack_type=RATE_LIMIT action=BLOCKED")

        # Log to database with attack_type = 'RATE_LIMIT'
        db.log_request(timestamp, client_ip, method, path, 'BLOCKED',
                       attack_type='RATE_LIMIT', matched_pattern=None)

        # Return 429 Too Many Requests
        html_body = """
        <!DOCTYPE html>
        <html>
        <head><title>429 Too Many Requests</title></head>
        <body>
            <h1>429 Too Many Requests</h1>
            <p>Rate limit exceeded. Please slow down.</p>
        </body>
        </html>
        """
        return Response(html_body, status=429, mimetype='text/html')

    # ---------- 3. WAF rule checking (only if not rate limited) ----------
    method = request.method
    full_url = request.url                     # e.g. http://localhost:5000/search?q=test
    path = request.path                        # e.g. /search
    query_params = request.args.to_dict(flat=False)  # preserves multiple values
    headers = dict(request.headers)            # all incoming HTTP headers
    cookies = request.cookies.to_dict()        # incoming cookies
    client_ip = get_client_ip()                # client IP address (proxy-aware)
    raw_body = request.get_data()              # raw request body (bytes)

    # Parse JSON if the request Content-Type is application/json
    json_data = None
    if request.is_json:
        json_data = request.get_json(silent=True)

    # Parse form data (application/x-www-form-urlencoded)
    form_data = request.form.to_dict(flat=False)

    # Store everything in a dict
    request_data = {
        "method": method,
        "full_url": full_url,
        "path": path,
        "query_params": query_params,
        "headers": headers,
        "cookies": cookies,
        "client_ip": client_ip,
        "raw_body": raw_body.decode('utf-8', errors='replace'),
        "form_data": form_data,
        "json_data": json_data
    }

    result = check_request(request_data)

    if result["is_attack"]:
        attack_type = result["attack_type"]
        matched_pattern = result["matched_pattern"]
        timestamp = get_timestamp()

        print(f"[{timestamp}] IP={client_ip} "
              f"attack_type={attack_type} "
              f"matched_pattern={matched_pattern} "
              f"action=BLOCKED")

        db.log_request(timestamp, client_ip, method, path, 'BLOCKED',
                       attack_type, matched_pattern)

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head><title>403 Forbidden</title></head>
        <body>
            <h1>403 Forbidden</h1>
            <p>Request blocked by WAF. Reason: {attack_type} rule triggered.</p>
        </body>
        </html>
        """
        return Response(html_body, status=403, mimetype='text/html')

    # If no attack detected, log and forward
    timestamp = get_timestamp()
    print(f"[{timestamp}] IP={client_ip} path={path} action=ALLOWED")
    db.log_request(timestamp, client_ip, method, path, 'ALLOWED')

    # ---------- 3. Forward the request to the target app ----------
    target_base = os.environ.get("TARGET_APP_URL", "http://localhost:5001")
    target_url = target_base + path

    # Copy incoming headers, but remove Host and Cookie.
    # Host: we let requests set the correct target Host header.
    # Cookie: we will pass cookies separately via the cookies parameter.
    forward_headers = dict(request.headers)
    forward_headers.pop('Host', None)
    forward_headers.pop('Cookie', None)

    try:
        # Forward the request with the same method, path, query params, body, and cookies.
        # allow_redirects=False makes the proxy transparent (does not follow redirects itself).
        target_response = requests.request(
            method=method,
            url=target_url,
            params=query_params,          # query string as dict with list values
            headers=forward_headers,
            cookies=cookies,
            data=raw_body,                # raw body bytes
            allow_redirects=False
        )
    except requests.exceptions.RequestException as e:
        # If the target app is unreachable, return a 502 Bad Gateway response.
        return Response(f"Proxy error: {e}", status=502)

    # ---------- 4. Return the target's response unchanged ----------
    response_headers = dict(target_response.headers)

    # Remove hop-by-hop headers that must not be forwarded by a proxy.
    # These headers are connection-specific and will be regenerated by Flask.
    for header in ['content-encoding', 'content-length', 'transfer-encoding', 'connection']:
        response_headers.pop(header, None)

    # Return the target's body, status code, and headers.
    return Response(
        target_response.content,
        status=target_response.status_code,
        headers=response_headers
    )


if __name__ == '__main__':
    # Create the database and table if they don't exist yet
    app.run(host='0.0.0.0', port=5000)