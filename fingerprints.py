from typing import Dict
import re

def fingerprint_technologies(response) -> Dict:

    #Given a requests.Response, return a dict of detected technologies

    tech = {}
    headers = response.headers
    body = response.text.lower() if response.text else ""

    server = headers.get("server", "")
    if server:
        tech["server"] = server.lower()

    if "cloudflare" in server.lower():
        tech["cdn"] = "cloudflare"

    if "x-powered-by" in headers:
        tech["powered_by"] = headers["x-powered-by"]

    # Framework detection
    if "astro" in body:
        tech["framework"] = "astro"

    if "__next" in body:
        tech["framework"] = "nextjs"

    if "wp-content" in body or "wordpress" in body:
        tech["framework"] = "wordpress"

    if "laravel" in body:
        tech["framework"] = "laravel"

    # Language hints
    if "php" in body:
        tech["language"] = "php"

    if "node" in server.lower() or "express" in body:
        tech["language"] = "nodejs"

    # Analytics
    if "googletagmanager" in body or "google-analytics" in body:
        tech["analytics"] = "google-analytics"

    if "cloudflareinsights" in body:
        tech["analytics"] = "cloudflare-insights"

    # WAF / edge
    if "cf-ray" in headers:
        tech["waf"] = "cloudflare"

    # Version hints
    version_match = re.search(r"astro@(\d+\.\d+\.\d+)", body)
    if version_match:
        tech["framework_version"] = version_match.group(1)

    return tech

