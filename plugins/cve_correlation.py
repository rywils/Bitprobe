from plugins.base_plugin import BasePlugin, Finding
from typing import Dict, List

from scanner.cve_db import load_cve_db
from scanner.fingerprints import fingerprint_technologies
from scanner.version_utils import versions_match


class CVECorrelationPlugin(BasePlugin):

    def get_name(self) -> str:
        return "cve_correlation"

    def get_description(self) -> str:
        return "Correlates detected technologies with known CVEs from a local database"

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings: List[Finding] = []

        # ✅ Only run once at root
        if url_info.get("depth", 0) > 0:
            return findings

        url = url_info["url"]
        response = request_handler.get(url)
        if not response:
            return findings

        tech = fingerprint_technologies(response)
        if not tech:
            return findings

        cve_db = load_cve_db()
        if not cve_db:
            return findings

        detected_products = []

        if "framework" in tech:
            detected_products.append(("framework", tech["framework"], tech.get("framework_version")))

        if "server" in tech:
            detected_products.append(("server", tech["server"], None))

        if "language" in tech:
            detected_products.append(("language", tech["language"], None))

        for category, product_value, detected_version in detected_products:
            product_value_lower = product_value.lower()

            for entry in cve_db:
                db_product = entry.get("product", "").lower()
                db_version = entry.get("version", "any")

                if not db_product:
                    continue

                if db_product not in product_value_lower:
                    continue

                if not versions_match(db_version, detected_version):
                    continue

                severity = entry.get("severity", "medium").lower()
                if severity not in ["critical", "high", "medium", "low", "info"]:
                    severity = "medium"

                cve_id = entry.get("cve_id", "UNKNOWN")
                summary = entry.get("summary", "No summary provided.")
                cvss = entry.get("cvss", None)
                references = entry.get("references", [])

                # ✅ PROFESSIONAL REPORT FIELDS
                attack_scenario = (
                    f"This vulnerability ({cve_id}) affects {db_product} and may allow attackers "
                    f"to compromise the availability, integrity, or confidentiality of the application "
                    f"depending on deployment and configuration."
                )

                defense_strategy = (
                    "Defensive mitigation includes timely patch management, secure configuration of "
                    "the affected component, least-privilege access controls, and continuous monitoring "
                    "for abnormal behavior."
                )

                mitigation_plan = (
                    "The IT team should identify all systems running this product and version, validate "
                    "patch availability in a staging environment, schedule a controlled rollout to production, "
                    "and confirm remediation via rescanning. Related security controls should be reviewed "
                    "for defense-in-depth."
                )

                evidence = {
                    "category": category,
                    "detected_product": product_value,
                    "detected_version": detected_version,
                    "cve_id": cve_id,
                    "cvss": cvss,
                    "references": references
                }

                remediation = (
                    "Review vendor advisories for this CVE and apply the recommended patches or upgrades. "
                    "Ensure affected components are updated across all environments."
                )

                finding = Finding(
                    plugin_name=self.get_name(),
                    severity=severity,
                    title=f"CVE Correlation: {cve_id} affecting {db_product}",
                    description=summary,
                    url=url,
                    evidence=evidence,
                    remediation=remediation,

                    # ✅ New professional fields
                    attack_scenario=attack_scenario,
                    defense_strategy=defense_strategy,
                    mitigation_plan=mitigation_plan
                )

                findings.append(finding)

        return findings
