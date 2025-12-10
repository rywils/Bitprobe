def prioritize_findings(findings):
    ranked = sorted(
        findings,
        key=lambda f: f.risk_score(),
        reverse=True
    )

    priorities = []

    for idx, f in enumerate(ranked, 1):
        priorities.append({
            "priority": idx,
            "title": f.title,
            "risk_score": f.risk_score(),
            "impact": f.impact,
            "likelihood": f.likelihood,
            "exposure": f.exposure,
            "business_risk": f.attack_scenario,
            "fix": f.mitigation_plan,
        })

    return priorities
