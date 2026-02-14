"""
HTTP client wrapper for making requests to target applications.

Provides session management, retry logic, rate limiting, and error handling.
All configuration values are read from config.py for consistency.
"""

import time
import threading
from collections import defaultdict
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Dict, Optional, Any
from .logger import get_logger
from config import (
    REQUEST_TIMEOUT,
    MAX_RETRIES,
    USER_AGENT,
    REQUEST_DELAY,
    VERIFY_SSL,
    FOLLOW_REDIRECTS,
    CIRCUIT_BREAKER_THRESHOLD,
)

logger = get_logger(__name__)


class HTTPClient:
    """
    Wrapper around requests.Session with retry logic, rate limiting, and timeout handling.

    Features:
    - Automatic retry on network failures
    - Configurable timeouts (from config.py)
    - Rate limiting between requests
    - Custom user-agent headers
    - Session persistence for cookies
    - Request counting for reporting
    - SSL verification control
    """

    def __init__(
        self,
        timeout: int = None,
        max_retries: int = None,
        user_agent: Optional[str] = None,
        request_delay: float = None,
        verify_ssl: bool = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize HTTP client with session and retry configuration.

        Args:
            timeout: Request timeout in seconds (default from config)
            max_retries: Maximum number of retries on failure (default from config)
            user_agent: Custom User-Agent header (default from config)
            request_delay: Delay between requests in seconds (default from config)
            verify_ssl: Whether to verify SSL certificates (default from config)
            cookies: Optional cookies to set on the session
            headers: Optional additional headers
        """
        self.timeout = timeout if timeout is not None else REQUEST_TIMEOUT
        self.request_delay = request_delay if request_delay is not None else REQUEST_DELAY
        self.verify_ssl = verify_ssl if verify_ssl is not None else VERIFY_SSL
        self.request_count = 0
        self._last_request_time = 0.0

        # Circuit breaker: track consecutive failures per URL path
        self._failure_counts: Dict[str, int] = defaultdict(int)
        self._failure_lock = threading.Lock()
        self._suppressed_errors: Dict[str, int] = defaultdict(int)

        self.session = requests.Session()
        self.session.verify = self.verify_ssl

        # Configure retry strategy
        retries = max_retries if max_retries is not None else MAX_RETRIES
        retry_strategy = Retry(
            total=retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set default headers
        ua = user_agent or USER_AGENT
        self.session.headers.update({
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

        # Add custom headers
        if headers:
            self.session.headers.update(headers)

        # Set cookies if provided
        if cookies:
            self.session.cookies.update(cookies)

    def _circuit_key(self, url: str) -> str:
        """Extract URL key for circuit breaker tracking (host + path)."""
        try:
            parsed = urlparse(url)
            return f"{parsed.netloc}{parsed.path}" if parsed.netloc else url
        except Exception:
            return url

    def _is_circuit_open(self, url: str) -> bool:
        """Check if circuit breaker is tripped for this URL path."""
        key = self._circuit_key(url)
        with self._failure_lock:
            return self._failure_counts[key] >= CIRCUIT_BREAKER_THRESHOLD

    def _record_failure(self, url: str):
        """Record a failure for circuit breaker tracking."""
        key = self._circuit_key(url)
        with self._failure_lock:
            self._failure_counts[key] += 1
            count = self._failure_counts[key]
        if count == CIRCUIT_BREAKER_THRESHOLD:
            logger.warning(
                f"Circuit breaker tripped for {key} after "
                f"{CIRCUIT_BREAKER_THRESHOLD} consecutive timeouts — "
                f"skipping further requests to this endpoint"
            )

    def _record_success(self, url: str):
        """Reset failure count on success."""
        key = self._circuit_key(url)
        with self._failure_lock:
            suppressed = self._suppressed_errors.pop(key, 0)
            if self._failure_counts[key] > 0:
                self._failure_counts[key] = 0
                if suppressed:
                    logger.info(f"Connection to {key} recovered ({suppressed} errors suppressed)")

    def _rate_limit(self):
        """Enforce rate limiting between requests."""
        if self.request_delay > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.request_delay:
                time.sleep(self.request_delay - elapsed)
        self._last_request_time = time.time()

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Perform GET request with error handling and rate limiting.

        Args:
            url: Target URL
            params: Query parameters
            **kwargs: Additional arguments passed to requests.get

        Returns:
            Response object or None if request failed
        """
        if self._is_circuit_open(url):
            key = self._circuit_key(url)
            with self._failure_lock:
                self._suppressed_errors[key] += 1
            return None

        self._rate_limit()
        try:
            self.request_count += 1
            response = self.session.get(
                url,
                params=params,
                timeout=self.timeout,
                allow_redirects=FOLLOW_REDIRECTS,
                **kwargs
            )
            self._record_success(url)
            return response
        except requests.exceptions.RequestException as e:
            self._record_failure(url)
            if not self._is_circuit_open(url):
                logger.error(f"GET request failed for {url}: {e}")
            return None

    def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Perform POST request with error handling and rate limiting.

        Args:
            url: Target URL
            data: Form data or body
            json: JSON body
            **kwargs: Additional arguments passed to requests.post

        Returns:
            Response object or None if request failed
        """
        if self._is_circuit_open(url):
            key = self._circuit_key(url)
            with self._failure_lock:
                self._suppressed_errors[key] += 1
            return None

        self._rate_limit()
        try:
            self.request_count += 1
            response = self.session.post(
                url,
                data=data,
                json=json,
                timeout=self.timeout,
                allow_redirects=FOLLOW_REDIRECTS,
                **kwargs
            )
            self._record_success(url)
            return response
        except requests.exceptions.RequestException as e:
            self._record_failure(url)
            if not self._is_circuit_open(url):
                logger.error(f"POST request failed for {url}: {e}")
            return None

    def head(
        self,
        url: str,
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Perform HEAD request with error handling.

        Args:
            url: Target URL
            **kwargs: Additional arguments

        Returns:
            Response object or None if request failed
        """
        if self._is_circuit_open(url):
            key = self._circuit_key(url)
            with self._failure_lock:
                self._suppressed_errors[key] += 1
            return None

        self._rate_limit()
        try:
            self.request_count += 1
            response = self.session.head(
                url,
                timeout=self.timeout,
                allow_redirects=FOLLOW_REDIRECTS,
                **kwargs
            )
            self._record_success(url)
            return response
        except requests.exceptions.RequestException as e:
            self._record_failure(url)
            if not self._is_circuit_open(url):
                logger.error(f"HEAD request failed for {url}: {e}")
            return None

    def close(self):
        """Close the session and release resources."""
        self.session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

