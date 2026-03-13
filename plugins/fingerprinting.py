from plugins.base_plugin import BasePlugin, Finding
from typing import Dict, List
from scanner.fingerprints import fingerprint_technologies

class FingerprintingPlugin(BasePlugin):

    def get_name(self) -> str:
        return "fingerprinting"

    def get_description(self) -> str:
        return "Passive technology fingerprinting (server, framework, language, CDN, analytics)"

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings = []
        url = url_info["url"]

        # ✅ Only fingerprint once at root
        if url_info.get("depth", 0) > 0:
            return findings

        response = request_handler.get(url)
        if not response:
            return findings

        # ✅ Use shared fingerprint helper
        tech = fingerprint_technologies(response)

        if not tech:
            return findings

        finding = Finding(
            plugin_name=self.get_name(),
            severity="info",
            title="Technology Fingerprinting",
            description="Passive identification of technologies used by the target",
            url=url,
            evidence=tech,
            remediation="Use this information to correlate against known CVEs and version-specific vulnerabilities."
        )

        findings.append(finding)
        return findings
