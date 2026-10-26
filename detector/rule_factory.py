from .rules import (SuspiciousLinksRule, SenderAddressRule, UrgentLanguageRule,
                    KnownPhishingFeedRule, MLDomainRule)


class RuleFactory:
    _rules = {
        "suspicious_links": SuspiciousLinksRule,
        "sender_address": SenderAddressRule,
        "urgent_language": UrgentLanguageRule,
        "known_phishing_feed": KnownPhishingFeedRule,
        "ml_url_classifier": MLDomainRule,
    }

    @classmethod
    def get_rule(cls, rule_type):
        try:
            return cls._rules[rule_type]()
        except KeyError:
            raise ValueError(f"Unknown rule type: {rule_type}")

    @classmethod
    def all_rule_names(cls):
        return list(cls._rules)
