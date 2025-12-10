from plugins.base_plugin import BasePlugin, Finding
from typing import Dict, List
import socket
from urllib.parse import urlparse


class NetworkScannerPlugin(BasePlugin):
    """
    Performs basic TCP port scanning and light banner grabbing.
    This is SAFE, non-exploitative, and client-report friendly.
    """

    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
    }

    def get_name(self) -> str:
        return "network_scanner"

    def get_description(self) -> str:
        return "Performs TCP port scanning and basic service fingerprinting"

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings: List[Finding] = []

        # ✅ Only scan once at root
        if url_info.get("depth", 0) > 0:
            return findings

        url = url_info["url"]
        parsed = urlparse(url)
        host = parsed.hostname

        if not host:
            return findings

        open_ports = []

        for port, service in self.COMMON_PORTS.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            try:
                result = sock.connect_ex((host, port))

                if result == 0:
                    banner = self._grab_banner(sock)
                    open_ports.append((port, service, banner))

            except Exception:
                pass
            finally:
                sock.close()

        for port, service, banner in open_ports:
            severity = "high" if port in [22, 3306, 5432, 6379, 27017] else "medium"

            attack_scenario = (
                f"An attacker could directly interact with the exposed {service} service on port {port}. "
                f"If authentication is weak or misconfigured, this could allow unauthorized system access, "
                f"data extraction, or full infrastructure compromise."
            )

            defense_strategy = (
                "Exposed services should be restricted using network firewalls, access control lists (ACLs), "
                "and zero-trust segmentation. Only systems that explicitly require access should be permitted."
            )

            mitigation_plan = (
                "The IT team should review firewall rules, confirm that the exposed service is required, "
                "enforce strong authentication, disable unused services, and verify remediation via rescanning."
            )

            finding = Finding(
                plugin_name=self.get_name(),
                severity=severity,
                title=f"Open Network Port Detected: {port} ({service})",
                description=f"The service {service} is exposed on TCP port {port}.",
                url=f"{host}:{port}",
                evidence={
                    "port": port,
                    "service": service,
                    "banner": banner,
                },
                remediation=(
                    f"If {service} is not required to be publicly accessible, restrict access via firewall rules. "
                    f"Otherwise, enforce authentication, encryption, and continuous monitoring."
                ),
                attack_scenario=attack_scenario,
                defense_strategy=defense_strategy,
                mitigation_plan=mitigation_plan,
            )

            findings.append(finding)

        return findings

    def _grab_banner(self, sock) -> str:
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024)
            return banner.decode(errors="ignore").strip()
        except Exception:
            return "No banner"
