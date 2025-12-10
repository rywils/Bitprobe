# plugins/base_plugin.py

from abc import ABC, abstractmethod
from typing import List, Dict, Optional


class Finding:
    """
    Core finding object used by all plugins.

    Supports:
      - Basic vulnerability metadata
      - Narrative fields (attack_scenario, defense_strategy, mitigation_plan)
      - Quantitative risk dimensions (impact, likelihood, exposure)
      - Optional explicit risk_score set by the engine
    """

    def __init__(
        self,
        plugin_name: str,
        severity: str,
        title: str,
        description: str,
        url: str,
        evidence: Dict,
        remediation: str,
        attack_scenario: str = "",
        defense_strategy: str = "",
        mitigation_plan: str = "",
        impact: int = 1,
        likelihood: int = 1,
        exposure: int = 1,
        risk_score: Optional[float] = None,
    ):
        self.plugin_name = plugin_name
        self.severity = severity
        self.title = title
        self.description = description
        self.url = url
        self.evidence = evidence
        self.remediation = remediation

        # Narrative / report-friendly fields
        self.attack_scenario = attack_scenario
        self.defense_strategy = defense_strategy
        self.mitigation_plan = mitigation_plan

        # Quantitative risk dimensions (1–5)
        self.impact = impact
        self.likelihood = likelihood
        self.exposure = exposure

        # Optional explicit risk score (can be set by the engine)
        self.risk_score: Optional[float] = risk_score

    def computed_risk_score(self) -> float:
        """
        If an explicit risk_score was set by the engine, use that.
        Otherwise, derive it from impact × likelihood × exposure, normalized to 0–100.
        """
        if self.risk_score is not None:
            return float(self.risk_score)

        raw = self.impact * self.likelihood * self.exposure  # max 5*5*5 = 125
        return min((raw / 125.0) * 100.0, 100.0)

    def to_dict(self) -> Dict:
        return {
            "plugin": self.plugin_name,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "attack_scenario": self.attack_scenario,
            "defense_strategy": self.defense_strategy,
            "mitigation_plan": self.mitigation_plan,
            "impact": self.impact,
            "likelihood": self.likelihood,
            "exposure": self.exposure,
            "risk_score": self.computed_risk_score(),
        }


class BasePlugin(ABC):
    def __init__(self, config=None):
        self.config = config or {}
        self.findings: List[Finding] = []

    @abstractmethod
    def get_name(self) -> str:
        pass

    @abstractmethod
    def get_description(self) -> str:
        pass

    @abstractmethod
    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        pass
