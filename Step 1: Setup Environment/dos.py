
# dos.py — Minimal DoS rate limiting helper for Flask

import time
from collections import defaultdict
from typing import Optional
from flask import Request

WINDOW = 10         # seconds
MAX_REQUESTS = 20   # per window

_requests = defaultdict(list)  # ip -> [timestamps]

def check_dos(request: Request) -> Optional[tuple]:
    """
    Returns a Flask-style (message, status_code) tuple if blocked, else None.
    To be called inside @app.before_request hook.
    """
    ip = request.remote_addr or "unknown"
    now = time.time()
    bucket = _requests[ip]

    # drop entries outside window
    while bucket and now - bucket[0] > WINDOW:
        bucket.pop(0)

    if len(bucket) >= MAX_REQUESTS:
        return ("Too many requests (DoS protection). Try later.", 429)

    bucket.append(now)
    return None
