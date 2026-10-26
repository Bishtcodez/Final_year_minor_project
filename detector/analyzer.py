from .rule_factory import RuleFactory


def analyze_email(email):
    """Run every rule and return score, verdict and human-readable reasons."""
    details, total = {}, 0
    for name in RuleFactory.all_rule_names():
        rule = RuleFactory.get_rule(name)
        findings = rule.analyze(email)
        points = sum(p for p, _ in findings)
        total += points
        details[name] = {"flagged": points >= rule.threshold, "score": points,
                         "reasons": [r for _, r in findings]}
    flagged_rules = sum(d["flagged"] for d in details.values())
    if details["known_phishing_feed"]["flagged"] or total >= 7 or flagged_rules >= 2:
        verdict = "Phishing"
    elif total >= 2:
        verdict = "Suspicious"
    else:
        verdict = "No known indicator detected"  # not a guarantee of safety
    return {"verdict": verdict, "total_score": total, "rules": details}
