from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from datetime import datetime
import os


class PDFReportGenerator:
    def __init__(self, report_data: dict, output_directory: str, client_name: str):
        self.report_data = report_data
        self.output_directory = output_directory
        self.client_name = client_name
        self.styles = getSampleStyleSheet()
        self.timestamp = datetime.now().strftime("%B %d, %Y")

    def generate(self):
        pdf_path = os.path.join(self.output_directory, "report.pdf")

        doc = SimpleDocTemplate(
            pdf_path,
            pagesize=LETTER,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
        )

        elements = []

        stats = self.report_data.get("statistics", {})
        severity_stats = stats.get("findings_by_severity", {})
        risk = stats.get("risk", {})

        # COVER
        elements.append(Paragraph("NexProbe Security Assessment Report", self.styles["Title"]))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph(f"<b>Client:</b> {self.client_name}", self.styles["Normal"]))
        elements.append(Paragraph(f"<b>Target:</b> {self.report_data.get('target')}", self.styles["Normal"]))
        elements.append(Paragraph(f"<b>Date:</b> {self.timestamp}", self.styles["Normal"]))
        elements.append(Paragraph(f"<b>Scan ID:</b> {self.report_data.get('scan_id')}", self.styles["Normal"]))

        elements.append(PageBreak())

        # EXEC SUMMARY
        elements.append(Paragraph("Executive Summary", self.styles["Heading1"]))
        elements.append(Spacer(1, 0.2 * inch))

        summary_text = (
            "This report presents the results of an automated security assessment performed using NexProbe. "
            "The objective of this assessment was to identify vulnerabilities, misconfigurations, and known "
            "security risks that could impact the target system."
        )
        elements.append(Paragraph(summary_text, self.styles["Normal"]))
        elements.append(Spacer(1, 0.2 * inch))

        elements.append(Paragraph("Overall Risk Posture", self.styles["Heading2"]))
        elements.append(Spacer(1, 0.1 * inch))

        elements.append(
            Paragraph(
                f"Overall Risk Level: <b>{risk.get('level', 'unknown').upper()}</b>",
                self.styles["Normal"],
            )
        )
        elements.append(
            Paragraph(
                f"Risk Score: {risk.get('normalized_score', 0)} / 100 "
                f"(raw: {risk.get('raw_score', 0)})",
                self.styles["Normal"],
            )
        )
        elements.append(Spacer(1, 0.2 * inch))

        elements.append(Paragraph("Risk Overview by Severity", self.styles["Heading2"]))
        for sev, count in severity_stats.items():
            if count > 0:
                elements.append(
                    Paragraph(f"{sev.upper()}: {count}", self.styles["Normal"])
                )

        elements.append(Spacer(1, 0.2 * inch))
        elements.append(
            Paragraph(
                f"Total Findings: {stats.get('total_findings', 0)}", self.styles["Normal"]
            )
        )
        elements.append(
            Paragraph(
                f"URLs Scanned: {stats.get('urls_scanned')}", self.styles["Normal"]
            )
        )
        elements.append(
            Paragraph(
                f"Scan Duration: {stats.get('duration_seconds')} seconds",
                self.styles["Normal"],
            )
        )

        elements.append(PageBreak())

        # DETAILED FINDINGS
        elements.append(Paragraph("Detailed Findings", self.styles["Heading1"]))
        elements.append(Spacer(1, 0.2 * inch))

        findings = self.report_data.get("findings", [])

        if not findings:
            elements.append(
                Paragraph(
                    "No security issues were detected during this scan.",
                    self.styles["Normal"],
                )
            )
        else:
            for idx, finding in enumerate(findings, 1):
                elements.append(
                    Paragraph(f"{idx}. {finding['title']}", self.styles["Heading2"])
                )
                elements.append(
                    Paragraph(
                        f"Severity: {finding['severity'].upper()}",
                        self.styles["Normal"],
                    )
                )

                if finding.get("risk_score") is not None:
                    elements.append(
                        Paragraph(
                            f"Risk Score (per finding): {finding['risk_score']}",
                            self.styles["Normal"],
                        )
                    )

                elements.append(
                    Paragraph(f"Affected URL: {finding['url']}", self.styles["Normal"])
                )
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Description", self.styles["Heading3"]))
                elements.append(
                    Paragraph(finding["description"], self.styles["Normal"])
                )
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Attack Scenario", self.styles["Heading3"]))
                elements.append(
                    Paragraph(
                        finding.get("attack_scenario", "Not provided."),
                        self.styles["Normal"],
                    )
                )
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Defense Strategy", self.styles["Heading3"]))
                elements.append(
                    Paragraph(
                        finding.get("defense_strategy", "Not provided."),
                        self.styles["Normal"],
                    )
                )
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Mitigation Plan", self.styles["Heading3"]))
                elements.append(
                    Paragraph(
                        finding.get("mitigation_plan", "Not provided."),
                        self.styles["Normal"],
                    )
                )
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Remediation", self.styles["Heading3"]))
                elements.append(
                    Paragraph(finding["remediation"], self.styles["Normal"])
                )
                elements.append(PageBreak())

        doc.build(elements)
        return pdf_path
