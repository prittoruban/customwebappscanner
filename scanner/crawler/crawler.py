"""
Web crawler for discovering URLs and extracting forms from target applications.

Performs breadth-first crawling within the same domain, extracting:
- Links (<a> tags)
- Forms with their actions, methods, and input fields
"""

from urllib.parse import urljoin, urlparse
from typing import List, Set, Dict, Any, Optional
from bs4 import BeautifulSoup
from dataclasses import dataclass, field

from utils.http import HTTPClient
from utils.logger import get_logger
from config import DEFAULT_CRAWL_DEPTH, MAX_CRAWL_URLS, MAX_FORMS_PER_PAGE

logger = get_logger(__name__)


@dataclass
class FormField:
    """Represents an input field within a form."""
    name: str
    field_type: str  # text, password, email, hidden, etc.
    value: str = ""


@dataclass
class Form:
    """
    Represents an HTML form with all its metadata.
    
    Used by vulnerability scanners to test form inputs.
    """
    action: str  # Form action URL (absolute)
    method: str  # GET or POST
    fields: List[FormField] = field(default_factory=list)
    url: str = ""  # The page URL where form was found
    
    def get_field_names(self) -> List[str]:
        """Return list of field names in this form."""
        return [f.name for f in self.fields if f.name]


class WebCrawler:
    """
    Web crawler that discovers URLs and extracts forms within a target domain.
    
    Features:
    - Respects same-domain policy
    - Configurable crawl depth
    - Extracts forms with complete metadata
    - Deduplicates URLs and forms
    """
    
    def __init__(
        self,
        start_url: str,
        max_depth: int = DEFAULT_CRAWL_DEPTH,
        http_client: Optional[HTTPClient] = None
    ):
        """
        Initialize the web crawler.
        
        Args:
            start_url: Starting URL for crawling
            max_depth: Maximum depth to crawl from start URL
            http_client: Optional HTTP client (creates new one if not provided)
        """
        self.start_url = start_url
        self.max_depth = max_depth
        self.http_client = http_client or HTTPClient()
        
        # Parse the base domain to enforce same-domain policy
        parsed = urlparse(start_url)
        self.base_domain = f"{parsed.scheme}://{parsed.netloc}"
        self.domain = parsed.netloc
        
        # Track visited URLs to avoid duplicates
        self.visited_urls: Set[str] = set()
        self.discovered_forms: List[Form] = []
    
    def _is_same_domain(self, url: str) -> bool:
        """
        Check if URL belongs to the same domain as start URL.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is in same domain, False otherwise
        """
        parsed = urlparse(url)
        return parsed.netloc == self.domain
    
    def _normalize_url(self, url: str, base_url: str) -> Optional[str]:
        """
        Convert relative URLs to absolute and normalize.
        
        Args:
            url: URL to normalize
            base_url: Base URL for resolving relative paths
            
        Returns:
            Normalized absolute URL or None if invalid
        """
        if not url or url.startswith('#') or url.startswith('javascript:'):
            return None
        
        # Convert to absolute URL
        absolute_url = urljoin(base_url, url)
        
        # Remove fragment
        absolute_url = absolute_url.split('#')[0]
        
        # Check if same domain
        if not self._is_same_domain(absolute_url):
            return None
        
        return absolute_url
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """
        Extract all valid links from a BeautifulSoup object.
        
        Args:
            soup: Parsed HTML
            base_url: Base URL for resolving relative links
            
        Returns:
            List of absolute URLs
        """
        links = []
        
        for anchor in soup.find_all('a', href=True):
            url = self._normalize_url(anchor['href'], base_url)
            if url and url not in self.visited_urls:
                links.append(url)
        
        return links
    
    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> List[Form]:
        """
        Extract all forms from a page with their complete metadata.
        
        Args:
            soup: Parsed HTML
            page_url: URL of the page containing the forms
            
        Returns:
            List of Form objects
        """
        forms = []
        
        for form_element in soup.find_all('form')[:MAX_FORMS_PER_PAGE]:
            # Get form action and method
            action = form_element.get('action', '')
            action = self._normalize_url(action, page_url) or page_url
            method = form_element.get('method', 'GET').upper()
            
            # Extract all input fields
            fields = []
            
            # Process <input> elements
            for input_elem in form_element.find_all('input'):
                field_name = input_elem.get('name', '')
                field_type = input_elem.get('type', 'text').lower()
                field_value = input_elem.get('value', '')
                
                if field_name:  # Only include named fields
                    fields.append(FormField(
                        name=field_name,
                        field_type=field_type,
                        value=field_value
                    ))
            
            # Process <textarea> elements
            for textarea in form_element.find_all('textarea'):
                field_name = textarea.get('name', '')
                if field_name:
                    fields.append(FormField(
                        name=field_name,
                        field_type='textarea',
                        value=textarea.get_text(strip=True)
                    ))
            
            # Process <select> elements
            for select in form_element.find_all('select'):
                field_name = select.get('name', '')
                if field_name:
                    # Get first option value as default
                    options = select.find_all('option')
                    value = options[0].get('value', '') if options else ''
                    fields.append(FormField(
                        name=field_name,
                        field_type='select',
                        value=value
                    ))
            
            # Only add forms that have at least one input field
            if fields:
                form = Form(
                    action=action,
                    method=method,
                    fields=fields,
                    url=page_url
                )
                forms.append(form)
                logger.debug(f"Extracted form: {method} {action} with {len(fields)} fields")
        
        return forms
    
    def crawl(self) -> List[Form]:
        """
        Perform breadth-first crawl starting from start_url.
        
        Returns:
            List of all discovered Form objects
        """
        logger.info(f"Starting crawl from {self.start_url} (max depth: {self.max_depth})")
        
        # Queue: (url, depth)
        to_visit = [(self.start_url, 0)]
        
        while to_visit and len(self.visited_urls) < MAX_CRAWL_URLS:
            url, depth = to_visit.pop(0)
            
            # Skip if already visited or depth exceeded
            if url in self.visited_urls or depth > self.max_depth:
                continue
            
            logger.info(f"Crawling [{depth}]: {url}")
            self.visited_urls.add(url)
            
            # Fetch page
            response = self.http_client.get(url)
            if not response or response.status_code != 200:
                logger.warning(f"Failed to fetch {url}")
                continue
            
            # Check if response is HTML
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                logger.debug(f"Skipping non-HTML content: {url}")
                continue
            
            # Parse HTML
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
            except Exception as e:
                logger.error(f"Failed to parse HTML from {url}: {e}")
                continue
            
            # Extract forms from this page
            forms = self._extract_forms(soup, url)
            self.discovered_forms.extend(forms)
            logger.info(f"Found {len(forms)} forms on {url}")
            
            # Extract links for further crawling (if not at max depth)
            if depth < self.max_depth:
                links = self._extract_links(soup, url)
                for link in links:
                    to_visit.append((link, depth + 1))
                logger.debug(f"Discovered {len(links)} new links at depth {depth}")
        
        logger.info(f"Crawl complete. Visited {len(self.visited_urls)} URLs, found {len(self.discovered_forms)} forms")
        return self.discovered_forms
