import time
from collections import defaultdict

WINDOW = 10        # Time window in seconds
MAX_REQUESTS = 20  # Maximum requests allowed in the time window

request_log = defaultdict(list)  # For each IP it store the timestamps of requests

def check_dos(request):  # A function to check for DoS attacks
    ip = request.remote_addr or "unknown"   # Get requester IP address
    now = time.time()   # Current timestamp
    timestamps = request_log[ip]  # List of timestamps for this IP

    # Remove timetamps that are outside the time window
    while timestamps and now - timestamps[0] > WINDOW:
        timestamps.pop(0)

    # If the number of requests exceed the limit, then block and return an error
    if len(timestamps) >= MAX_REQUESTS:
        return ("Too many requests, try again later.", 429)

    # Otherwise, allow and log the current request timestamp
    timestamps.append(now)
    return None
