from plugins.base_plugin import BasePlugin, Finding
from typing import List, Dict


class SecurityHeadersPlugin(BasePlugin):
    REQUIRED_HEADERS = {
        'X-Frame-Options': {
            'severity': 'medium',
            'description': 'Missing X-Frame-Options header allows clickjacking attacks',
            'remediation': 'Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" header'
        },
        'X-Content-Type-Options': {
            'severity': 'low',
            'description': 'Missing X-Content-Type-Options header allows MIME-sniffing attacks',
            'remediation': 'Add "X-Content-Type-Options: nosniff" header'
        },
        'Content-Security-Policy': {
            'severity': 'medium',
            'description': 'Missing Content-Security-Policy header allows various injection attacks',
            'remediation': 'Implement a Content-Security-Policy appropriate for your application'
        },
        'Strict-Transport-Security': {
            'severity': 'high',
            'description': 'Missing HSTS header on HTTPS site allows downgrade attacks',
            'remediation': 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header'
        }
    }

    def get_name(self) -> str:
        return "security_headers"

    def get_description(self) -> str:
        return "Checks for missing or misconfigured security headers"

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings = []
        url = url_info['url']

        response = request_handler.get(url)
        if not response:
            return findings

        headers = response.headers

        for header_name, header_info in self.REQUIRED_HEADERS.items():
            if header_name not in headers:
                if header_name == 'Strict-Transport-Security' and not url.startswith('https'):
                    continue

                attack_scenario = (
                    f"An attacker could exploit the absence of the {header_name} header to manipulate "
                    f"how the browser handles content or user interaction, potentially enabling attacks "
                    f"such as clickjacking, MIME-sniffing, or injection-based exploits."
                )

                defense_strategy = (
                    "Security headers enforce browser-side protections that restrict how content is interpreted, "
                    "loaded, and displayed. These headers act as a first line of defense against client-side attacks."
                )

                mitigation_plan = (
                    "The IT team should implement standardized security headers across all production systems, "
                    "validate behavior in a staging environment, and enforce these controls via the web server "
                    "or CDN configuration. Ongoing monitoring should ensure headers remain intact."
                )

                finding = Finding(
                    plugin_name=self.get_name(),
                    severity=header_info['severity'],
                    title=f"Missing {header_name} Header",
                    description=header_info['description'],
                    url=url,
                    evidence={'missing_header': header_name},
                    remediation=header_info['remediation'],
                    attack_scenario=attack_scenario,
                    defense_strategy=defense_strategy,
                    mitigation_plan=mitigation_plan
                )

                findings.append(finding)

        if 'X-Frame-Options' in headers:
            value = headers['X-Frame-Options'].upper()
            if value not in ['DENY', 'SAMEORIGIN']:
                attack_scenario = (
                    "An attacker could embed the application within a malicious iframe and trick users into "
                    "performing unintended actions through deceptive overlays (clickjacking)."
                )

                defense_strategy = (
                    "Properly configured X-Frame-Options prevents the site from being embedded by external origins, "
                    "neutralizing clickjacking attack vectors."
                )

                mitigation_plan = (
                    "Update the X-Frame-Options header to use a secure value (DENY or SAMEORIGIN), test for "
                    "compatibility, and enforce this configuration via centralized CDN or web server rules."
                )

                finding = Finding(
                    plugin_name=self.get_name(),
                    severity='medium',
                    title="Weak X-Frame-Options Configuration",
                    description=f"X-Frame-Options is set to '{headers['X-Frame-Options']}' which may not provide adequate protection",
                    url=url,
                    evidence={'header_value': headers['X-Frame-Options']},
                    remediation='Set X-Frame-Options to "DENY" or "SAMEORIGIN"',
                    attack_scenario=attack_scenario,
                    defense_strategy=defense_strategy,
                    mitigation_plan=mitigation_plan
                )

                findings.append(finding)

        return findings
