import re
from . import config
from .utils import deobfuscate, levenshtein, split_domain


def brand_lookalike(host):
    """Return (points, reason) if `host` imitates a known brand, else None."""
    d = split_domain(host)
    for brand, legit in config.BRANDS.items():
        if d["registered"] in legit:
            return None  # genuine brand domain (subdomains included)

    label = d["label"]
    variants = deobfuscate(label)
    squeezed = {v.replace("-", "") for v in variants} | {label.replace("-", "")}

    for brand in config.BRANDS:
        # 1. character substitution: amaz0n, paypa1, g00gle, rnicrosoft
        if label != brand and brand in variants:
            return 4, f"'{host}' imitates {brand} using look-alike characters"
        # 2. typosquatting: arnazon / amazzon / paypall
        if len(brand) >= 6:
            for v in squeezed:
                if v != brand and levenshtein(v, brand) <= (2 if len(brand) >= 8 else 1):
                    return 3, f"'{host}' is a near-spelling of {brand}"
        # 3. brand keyword stuffed into another domain: amazon-security.com
        tokens = set().union(*(re.split(r"[-_]", v) for v in variants))
        if brand in tokens or (len(brand) >= 6 and any(v.startswith(brand) or v.endswith(brand) for v in variants)):
            return 3, f"'{host}' uses the brand name {brand} but is not a {brand} domain"
        # 4. brand in subdomain: paypal.com.evil.net
        if brand in d["sub"].replace("-", "."):
            return 3, f"brand '{brand}' appears in the subdomain of '{host}'"
    return None
