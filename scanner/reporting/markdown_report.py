import os
from datetime import datetime


class MarkdownReportGenerator:
    def __init__(self, report_data: dict, output_directory: str, client_name: str):
        self.report_data = report_data
        self.output_directory = output_directory
        self.client_name = client_name
        self.timestamp = datetime.now().strftime("%B %d, %Y")

    def generate(self):
        os.makedirs(self.output_directory, exist_ok=True)
        output_path = os.path.join(self.output_directory, "report.md")

        md = []

        # COVER
        md.append("# NexProbe Security Assessment Report\n\n")
        md.append(f"**Client:** {self.client_name}  \n")
        md.append(f"**Target:** {self.report_data.get('target')}  \n")
        md.append(f"**Date:** {self.timestamp}  \n")
        md.append(f"**Scan ID:** {self.report_data.get('scan_id')}  \n")
        md.append("\n---\n")

        stats = self.report_data.get("statistics", {})
        severity_stats = stats.get("findings_by_severity", {})
        risk = stats.get("risk", {})

        # EXEC SUMMARY
        md.append("## Executive Summary\n\n")
        md.append(
            "This report presents the findings of an automated security assessment performed using **NexProbe**. "
            "The objective of this assessment was to identify security weaknesses, misconfigurations, and known "
            "vulnerabilities that could impact the confidentiality, integrity, or availability of the target system.\n\n"
        )

        md.append("### Overall Risk Posture\n\n")
        md.append(
            f"- **Overall Risk Level:** `{risk.get('level', 'unknown').upper()}`  \n"
        )
        md.append(
            f"- **Risk Score:** {risk.get('normalized_score', 0)} / 100 "
            f"(raw: {risk.get('raw_score', 0)})  \n\n"
        )

        md.append("### Risk Overview by Severity\n\n")
        for sev, count in severity_stats.items():
            if count > 0:
                md.append(f"- **{sev.upper()}**: {count}\n")

        md.append(f"\n**Total Findings:** {stats.get('total_findings', 0)}  \n")
        md.append(f"**URLs Scanned:** {stats.get('urls_scanned')}  \n")
        md.append(f"**Scan Duration:** {stats.get('duration_seconds')} seconds  \n")

        md.append("\n---\n")

        # DETAILED FINDINGS
        md.append("## Detailed Findings\n\n")

        if not self.report_data.get("findings"):
            md.append("✅ No security issues were detected during this scan.\n")
        else:
            for idx, finding in enumerate(self.report_data["findings"], 1):
                md.append(f"### {idx}. {finding['title']}\n")
                md.append(f"**Severity:** `{finding['severity'].upper()}`  \n")

                risk_score = finding.get("risk_score")
                if risk_score is not None:
                    md.append(f"**Risk Score (per finding):** {risk_score}  \n")

                md.append(f"**Affected URL:** {finding['url']}  \n\n")

                md.append("**Description:**\n")
                md.append(f"{finding['description']}\n\n")

                md.append("**Evidence:**\n")
                md.append("```json\n")
                md.append(f"{finding.get('evidence', {})}\n")
                md.append("```\n\n")

                md.append("### How an attacker may exploit this vulnerability\n")
                md.append(f"{finding.get('attack_scenario', 'Not provided.')}\n\n")

                md.append("### How defense would mitigate this attack vector\n")
                md.append(f"{finding.get('defense_strategy', 'Not provided.')}\n\n")

                md.append("### Plan for risk management and mitigation\n")
                md.append(f"{finding.get('mitigation_plan', 'Not provided.')}\n\n")

                md.append("**Remediation:**\n")
                md.append(f"{finding['remediation']}\n\n")
                md.append("---\n\n")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("".join(md))

        return output_path
