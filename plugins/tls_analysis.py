from plugins.base_plugin import BasePlugin, Finding
from typing import Dict, List
from urllib.parse import urlparse
import socket
import ssl
from datetime import datetime, timezone


class TLSAnalysisPlugin(BasePlugin):
    """
    Analyzes TLS configuration for the target host: certificate, expiry, protocol, cipher.
    """

    def get_name(self) -> str:
        return "tls_analysis"

    def get_description(self) -> str:
        return "Performs basic TLS inspection (certificate, expiry, protocol, cipher)"

    def _flatten_name(self, name_parts):
        """
        Safely flatten OpenSSL subject/issuer tuples into human-readable form.
        """
        flat = []
        for part in name_parts:
            for key, value in part:
                flat.append(f"{key}={value}")
        return ", ".join(flat)

    def _analyze_port(self, host: str, port: int) -> List[Finding]:
        findings: List[Finding] = []

        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()
        except Exception:
            return findings

        now = datetime.now(timezone.utc)
        not_after_str = cert.get("notAfter")
        not_after = None
        days_left = None

        if not_after_str:
            try:
                not_after = datetime.strptime(
                    not_after_str, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                days_left = (not_after - now).days
            except Exception:
                pass

        severity = "low"
        risk_reasons = []

        if not_after and now > not_after:
            severity = "high"
            risk_reasons.append("Certificate is expired.")
        elif not_after and days_left is not None and days_left < 30:
            severity = "medium"
            risk_reasons.append(f"Certificate expires soon ({days_left} days).")

        if protocol in ("TLSv1", "TLSv1.1"):
            if severity != "high":
                severity = "medium"
            risk_reasons.append(f"Weak or legacy TLS protocol in use: {protocol}.")

        subject = cert.get("subject", [])
        issuer = cert.get("issuer", [])

        subject_str = self._flatten_name(subject)
        issuer_str = self._flatten_name(issuer)

        description = (
            f"TLS is enabled on port {port} using protocol {protocol} with cipher {cipher[0]} "
            f"({cipher[2]}-bit)."
        )

        if risk_reasons:
            description += " " + " ".join(risk_reasons)

        attack_scenario = (
            "If TLS is misconfigured (expired certificate, weak protocols, or poor ciphers), attackers may "
            "intercept or manipulate traffic, downgrade encryption, or perform man-in-the-middle attacks."
        )

        defense_strategy = (
            "Use strong TLS configurations with modern protocols (TLS 1.2+), valid certificates, and "
            "trusted certificate authorities. Enforce HSTS where applicable."
        )

        mitigation_plan = (
            "The IT team should ensure all public services use modern TLS versions, renew certificates "
            "before expiration, disable weak protocols, and verify configurations through continuous monitoring."
        )

        evidence = {
            "port": port,
            "protocol": protocol,
            "cipher": cipher,
            "not_after": not_after_str,
            "days_until_expiry": days_left,
            "subject": subject_str,
            "issuer": issuer_str,
        }

        finding = Finding(
            plugin_name=self.get_name(),
            severity=severity,
            title=f"TLS Configuration on Port {port}",
            description=description,
            url=f"{host}:{port}",
            evidence=evidence,
            remediation=(
                "Renew certificates before expiration and ensure only modern TLS protocols and strong ciphers "
                "are enabled."
            ),
            attack_scenario=attack_scenario,
            defense_strategy=defense_strategy,
            mitigation_plan=mitigation_plan,
        )

        findings.append(finding)
        return findings

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings: List[Finding] = []

        # Only scan root
        if url_info.get("depth", 0) > 0:
            return findings

        url = url_info["url"]
        parsed = urlparse(url)
        host = parsed.hostname

        if not host:
            return findings

        # Standard TLS ports
        for port in [443, 8443]:
            findings.extend(self._analyze_port(host, port))

        return findings
