from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import Set, List, Dict
import re

class Crawler:
    def __init__(self, base_url: str, max_depth: int = 3, max_urls: int = 500):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited_urls = set()
        self.urls_to_scan = []
        
    def is_valid_url(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.netloc != self.base_domain:
            return False
        skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.ttf']
        if any(url.lower().endswith(ext) for ext in skip_extensions):
            return False
        return True
    
    def extract_links(self, html: str, current_url: str) -> List[str]:
        soup = BeautifulSoup(html, 'html.parser')
        links = []
        
        for tag in soup.find_all(['a', 'form']):
            if tag.name == 'a':
                href = tag.get('href')
                if href:
                    absolute_url = urljoin(current_url, href)
                    absolute_url = absolute_url.split('#')[0]
                    if self.is_valid_url(absolute_url):
                        links.append(absolute_url)
            elif tag.name == 'form':
                action = tag.get('action', '')
                absolute_url = urljoin(current_url, action)
                if self.is_valid_url(absolute_url):
                    links.append(absolute_url)
        
        return list(set(links))
    
    def crawl(self, request_handler) -> List[Dict]:
        queue = [(self.base_url, 0)]
        
        while queue and len(self.visited_urls) < self.max_urls:
            url, depth = queue.pop(0)
            
            if url in self.visited_urls or depth > self.max_depth:
                continue
            
            print(f"[*] Crawling: {url} (depth: {depth})")
            self.visited_urls.add(url)
            
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            self.urls_to_scan.append({
                'url': url,
                'params': params,
                'depth': depth
            })
            
            response = request_handler.get(url)
            if response and response.status_code == 200:
                if 'text/html' in response.headers.get('Content-Type', ''):
                    new_links = self.extract_links(response.text, url)
                    for link in new_links:
                        if link not in self.visited_urls:
                            queue.append((link, depth + 1))
        
        print(f"[+] Crawling complete. Found {len(self.urls_to_scan)} URLs")
        return self.urls_to_scan
