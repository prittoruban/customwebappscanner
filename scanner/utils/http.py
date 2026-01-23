"""
HTTP client wrapper for making requests to target applications.

Provides session management, retry logic, and error handling for HTTP requests.
Includes timeout protection and user-agent spoofing.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Dict, Optional, Any
from .logger import get_logger

logger = get_logger(__name__)


class HTTPClient:
    """
    Wrapper around requests.Session with retry logic and timeout handling.
    
    Features:
    - Automatic retry on network failures
    - Configurable timeouts
    - Custom user-agent headers
    - Session persistence for cookies
    """
    
    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 3,
        user_agent: Optional[str] = None
    ):
        """
        Initialize HTTP client with session and retry configuration.
        
        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries on failure
            user_agent: Custom User-Agent header (defaults to generic browser)
        """
        self.timeout = timeout
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
    
    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Perform GET request with error handling.
        
        Args:
            url: Target URL
            params: Query parameters
            **kwargs: Additional arguments passed to requests.get
            
        Returns:
            Response object or None if request failed
        """
        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.timeout,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"GET request failed for {url}: {e}")
            return None
    
    def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Perform POST request with error handling.
        
        Args:
            url: Target URL
            data: Form data or body
            **kwargs: Additional arguments passed to requests.post
            
        Returns:
            Response object or None if request failed
        """
        try:
            response = self.session.post(
                url,
                data=data,
                timeout=self.timeout,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"POST request failed for {url}: {e}")
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
