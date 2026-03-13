# scanner/engine.py

from scanner.config import ScanConfig
from scanner.request_handler import RequestHandler
from scanner.crawler import Crawler
from scanner.analysis.attack_chain_engine import build_attack_chains

from typing import List, Dict
import importlib
import time
from datetime import datetime


class ScanEngine:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.request_handler = RequestHandler(rate_limit=config.rate_limit)
        self.crawler = Crawler(
            config.target_url,
            config.depth,
            config.max_urls
        )
        self.plugins = []
        self.findings = []
        self.scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    def load_plugins(self):
        plugin_map = {
            "fingerprinting": "plugins.fingerprinting.FingerprintingPlugin",
            "security_headers": "plugins.security_headers.SecurityHeadersPlugin",
            "sensitive_files": "plugins.sensitive_files.SensitiveFilesPlugin",
            "cve_correlation": "plugins.cve_correlation.CVECorrelationPlugin",
            "network_scanner": "plugins.network_scanner.NetworkScannerPlugin",
            "tls_analysis": "plugins.tls_analysis.TLSAnalysisPlugin",
        }

        for plugin_name in self.config.enabled_plugins:
            if plugin_name in plugin_map:
                module_path, class_name = plugin_map[plugin_name].rsplit(".", 1)
                module = importlib.import_module(module_path)
                plugin_class = getattr(module, class_name)
                plugin = plugin_class(self.config)
                self.plugins.append(plugin)
                print(f"[+] Loaded plugin: {plugin.get_name()}")

    def run_scan(self):
        print(f"[*] Starting scan: {self.scan_id}")
        print(f"[*] Target: {self.config.target_url}")
        start_time = time.time()

        # Load plugins
        self.load_plugins()

        # Crawl target
        print("\n[*] Phase 1: Crawling target...")
        urls = self.crawler.crawl(self.request_handler)

        # Run plugins
        print(f"\n[*] Phase 2: Running {len(self.plugins)} plugins on {len(urls)} URLs...")
        for i, url_info in enumerate(urls):
            print(f"\n[*] Scanning URL {i + 1}/{len(urls)}: {url_info['url']}")
            for plugin in self.plugins:
                plugin_findings = plugin.scan(url_info, self.request_handler)
                self.findings.extend(plugin_findings)

                if plugin_findings:
                    print(f"  [!] {plugin.get_name()}: Found {len(plugin_findings)} issue(s)")

        duration = time.time() - start_time

        # ✅ Build attack chains
        attack_chains = build_attack_chains(self.findings)

        # ✅ Build report
        report = self._generate_report(duration, attack_chains)

        # ✅ Print summary
        self._print_summary(report)

        return report

    def _generate_report(self, duration: float, attack_chains: List[Dict]) -> Dict:
        findings_by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in self.findings:
            findings_by_severity[finding.severity] += 1

        return {
            "scan_id": self.scan_id,
            "target": self.config.target_url,
            "timestamp": datetime.now().isoformat(),
            "findings": [f.to_dict() for f in self.findings],
            "attack_chains": attack_chains,
            "statistics": {
                "urls_scanned": len(self.crawler.visited_urls),
                "duration_seconds": round(duration, 2),
                "findings_by_severity": findings_by_severity,
                "total_findings": len(self.findings),
            },
        }

    def _print_summary(self, report: Dict):
        print("\n" + "=" * 70)
        print("SCAN SUMMARY")
        print("=" * 70)
        print(f"Scan ID: {report['scan_id']}")
        print(f"Target: {report['target']}")
        print(f"Duration: {report['statistics']['duration_seconds']} seconds")
        print(f"URLs Scanned: {report['statistics']['urls_scanned']}")

        print("\nFindings by Severity:")
        for severity, count in report["statistics"]["findings_by_severity"].items():
            if count > 0:
                print(f"  {severity.upper()}: {count}")

        print(f"\nTotal Issues Found: {report['statistics']['total_findings']}")

        # ✅ Attack Chain Summary
        if report.get("attack_chains"):
            print("\n" + "=" * 70)
            print("ATTACK CHAIN ANALYSIS")
            print("=" * 70)

            for chain in report["attack_chains"]:
                print(f"\n• {chain['title']}")
                print(f"  Stage: {chain['kill_chain_stage']}")
                print(f"  Impact: {chain['business_impact']}")

        # ✅ Full Findings
        if self.findings:
            print("\n" + "-" * 70)
            print("DETAILED FINDINGS")
            print("-" * 70)

            for i, finding in enumerate(self.findings, 1):
                print(f"\n{i}. [{finding.severity.upper()}] {finding.title}")
                print(f"   URL: {finding.url}")
                print(f"   Description: {finding.description}")
                print(f"   Remediation: {finding.remediation}")

                if finding.attack_scenario:
                    print(f"   Attack Scenario: {finding.attack_scenario}")

                if finding.defense_strategy:
                    print(f"   Defense Strategy: {finding.defense_strategy}")

                if finding.mitigation_plan:
                    print(f"   Mitigation Plan: {finding.mitigation_plan}")

                print(f"   Risk Score: {round(finding.computed_risk_score(), 1)} / 100")
