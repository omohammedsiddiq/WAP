# rate_limiter.py
import time
import threading
from collections import deque

class SlidingWindowRateLimiter:
    """
    In-memory sliding-window rate limiter.
    Tracks requests per client IP using a deque of timestamps.
    """
    def __init__(self, max_requests=20, window_seconds=10):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.clients = {}          # IP -> deque of Unix timestamps
        self.lock = threading.Lock()

    def is_rate_limited(self, client_ip):
        """
        Check if the given client IP has exceeded the rate limit.

        Returns True if the request should be blocked, False otherwise.
        Also records the current request when allowed.
        """
        now = time.time()
        with self.lock:
            if client_ip in self.clients:
                dq = self.clients[client_ip]
                # Remove timestamps older than the sliding window
                while dq and now - dq[0] > self.window_seconds:
                    dq.popleft()

                # If already at limit, block (don't add this request)
                if len(dq) >= self.max_requests:
                    return True

                # Otherwise record the request
                dq.append(now)
            else:
                # First request from this IP
                self.clients[client_ip] = deque([now])

            # Periodic cleanup: remove empty deques if too many IPs tracked
            if len(self.clients) > 1000:
                self._cleanup_empty()

            return False

    def _cleanup_empty(self):
        """Remove IP entries with empty deques to free memory."""
        for ip in list(self.clients.keys()):
            if not self.clients[ip]:
                del self.clients[ip]