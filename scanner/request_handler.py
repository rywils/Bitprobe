import requests
import time
from urllib.parse import urljoin, urlparse
from typing import Dict, Optional

class RequestHandler:
    def __init__(self, rate_limit: int = 10, timeout: int = 10):
        self.session = requests.Session()
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.last_request_time = 0
        self.session.headers.update({
            'User-Agent': 'WebSecScanner/1.0 (Security Research Tool)'
        })
    
    def _respect_rate_limit(self):
        if self.rate_limit > 0:
            time_since_last = time.time() - self.last_request_time
            min_interval = 1.0 / self.rate_limit
            if time_since_last < min_interval:
                time.sleep(min_interval - time_since_last)
        self.last_request_time = time.time()
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            self._respect_rate_limit()
            response = self.session.get(url, timeout=self.timeout, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed for {url}: {str(e)}")
            return None
    
    def post(self, url: str, data: Dict = None, **kwargs) -> Optional[requests.Response]:
        try:
            self._respect_rate_limit()
            response = self.session.post(url, data=data, timeout=self.timeout, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed for {url}: {str(e)}")
            return None
