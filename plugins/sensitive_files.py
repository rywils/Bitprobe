from plugins.base_plugin import BasePlugin, Finding
from typing import List, Dict
from urllib.parse import urljoin, urlparse
import hashlib


class SensitiveFilesPlugin(BasePlugin):
    SENSITIVE_PATHS = [
        ".env",
        ".git/config",
        ".git/HEAD",
        "web.config",
        ".htaccess",
        "composer.json",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        ".DS_Store",
        "backup.zip",
        "backup.sql",
        "dump.sql",
        "db.sql",
        "database.sql",
        "admin",
        "phpinfo.php",
        "info.php",
        "test.php",
        "config.php.bak",
        "config.php~",
        "wp-config.php.bak",
    ]

    def get_name(self) -> str:
        return "sensitive_files"

    def get_description(self) -> str:
        return "Checks for exposed sensitive files and directories with content verification"

    def _hash_body(self, content: bytes) -> str:
        return hashlib.md5(content).hexdigest()

    def _looks_like_html(self, content: str) -> bool:
        lowered = content.lower()
        return (
            "<html" in lowered
            or "<body" in lowered
            or "<!doctype html" in lowered
        )

    def _looks_like_sql_dump(self, content: str) -> bool:
        lowered = content.lower()
        tokens = ["create table", "insert into", "alter table", "drop table", "database"]
        return any(t in lowered for t in tokens)

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings: List[Finding] = []
        base_url = url_info["url"]

        # Only run once at root
        if url_info.get("depth", 0) > 0:
            return findings

        parsed = urlparse(base_url)
        root_url = f"{parsed.scheme}://{parsed.netloc}/"

        # Establish baseline response for unknown paths (SPA/CDN fallbacks)
        baseline_response = request_handler.get(root_url)
        if not baseline_response:
            return findings

        baseline_hash = self._hash_body(baseline_response.content)
        baseline_length = len(baseline_response.content)
        baseline_ct = baseline_response.headers.get("Content-Type", "")

        for path in self.SENSITIVE_PATHS:
            test_url = urljoin(root_url, path)
            response = request_handler.get(test_url)

            if not response:
                continue

            if response.status_code != 200:
                continue

            current_hash = self._hash_body(response.content)
            current_length = len(response.content)
            current_ct = response.headers.get("Content-Type", "")

            try:
                body_text = response.text
            except Exception:
                body_text = ""

            # Same body as baseline => definitely fallback
            if current_hash == baseline_hash:
                continue

            # Very similar size = likely same template
            size_diff = abs(current_length - baseline_length)
            if size_diff < 100:
                if self._looks_like_html(body_text) and not path.lower().endswith(
                    (".html", ".htm", ".php")
                ):
                    continue

            # HTML content for obviously non-HTML sensitive paths? Probably error page.
            if "text/html" in current_ct.lower() and self._looks_like_html(body_text):
                if any(
                    path.lower().endswith(ext)
                    for ext in [".env", ".sql", ".bak", ".config", ".htaccess"]
                ):
                    # SQL-like names must actually look like SQL
                    if path.lower().endswith(".sql") or "dump" in path.lower():
                        if not self._looks_like_sql_dump(body_text):
                            continue
                    else:
                        continue

            # SQL-like filenames must actually look like SQL content
            if path.lower().endswith(".sql") or "dump" in path.lower():
                if not self._looks_like_sql_dump(body_text):
                    continue

            severity = (
                "high"
                if any(
                    x in path
                    for x in [".env", ".git", "backup", "dump", "db.sql", "database.sql"]
                )
                else "medium"
            )

            attack_scenario = (
                f"If an attacker gains access to the exposed file '{path}', they may extract sensitive "
                f"information such as credentials, internal configuration details, source code, or backup "
                f"data. This information could be used to escalate privileges or pivot further into internal systems."
            )

            defense_strategy = (
                "Sensitive files should never be directly exposed to the public internet. Defense involves "
                "restricting file access at the web server or CDN layer and ensuring that sensitive artifacts "
                "are stored outside of the web root."
            )

            mitigation_plan = (
                "The IT team should immediately remove publicly exposed sensitive files, audit deployment "
                "pipelines for accidental leakage, validate web root contents, and implement automated checks "
                "in CI/CD to prevent re-exposure in future builds."
            )

            finding = Finding(
                plugin_name=self.get_name(),
                severity=severity,
                title=f"Exposed Sensitive File: {path}",
                description=f"The file '{path}' is publicly accessible and appears to contain sensitive information.",
                url=test_url,
                evidence={
                    "path": path,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "content_type": current_ct,
                },
                remediation=f"Remove or restrict access to '{path}' using proper access controls.",
                attack_scenario=attack_scenario,
                defense_strategy=defense_strategy,
                mitigation_plan=mitigation_plan,
            )

            findings.append(finding)

        return findings
