import re
from . import config, feeds, ml
from .lookalike import brand_lookalike
from .utils import (deobfuscate, split_domain, get_host, extract_urls,
                    extract_anchors, parse_sender, clean_text)

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class Rule:
    name = "rule"
    threshold = 2  # points needed for check() to return True

    def analyze(self, email):
        """Return list of (points, reason)."""
        raise NotImplementedError

    def check(self, email):
        return self.score(email) >= self.threshold

    def score(self, email):
        return sum(p for p, _ in self.analyze(email))

    def reasons(self, email):
        return [r for _, r in self.analyze(email)]


class SuspiciousLinksRule(Rule):
    name = "suspicious_links"

    def _inspect_url(self, url):
        findings = []
        host, full = get_host(url)
        if not host:
            return findings
        d = split_domain(host)
        if d["registered"] in config.BLOCKLIST_DOMAINS:
            findings.append((3, f"'{host}' is on the blocklist"))
        if IP_RE.match(host):
            findings.append((3, f"link points to a raw IP address ({host})"))
        if "xn--" in host or any(ord(c) > 127 for c in host):
            findings.append((3, f"'{host}' uses internationalised/punycode characters (homograph attack)"))
        if "@" in full.split("//", 1)[-1].split("/", 1)[0]:
            findings.append((3, "URL contains '@' to disguise the real destination"))
        if d["suffix"].split(".")[-1] in config.SUSPICIOUS_TLDS:
            findings.append((1, f"suspicious top-level domain .{d['suffix']}"))
        if d["registered"] in config.URL_SHORTENERS:
            findings.append((1, f"shortened link ({host}) hides the destination"))
        if host.count(".") >= 4:
            findings.append((1, f"too many subdomains in '{host}'"))
        if d["label"].count("-") >= 2:
            findings.append((1, f"many hyphens in '{host}'"))
        if full.lower().startswith("http://"):
            findings.append((1, f"insecure http link ({host})"))
        look = brand_lookalike(host)
        if look:
            findings.append(look)
        return findings

    def analyze(self, email):
        findings, seen = [], set()
        body = email.get("body") or ""
        for url in extract_urls(body):
            for f in self._inspect_url(url):
                if f not in seen:
                    seen.add(f)
                    findings.append(f)
        # HTML links where the visible text shows one site but href goes elsewhere
        for href, text in extract_anchors(body):
            shown = extract_urls(text)
            if shown:
                a, b = split_domain(get_host(shown[0])[0]), split_domain(get_host(href)[0])
                if a["registered"] != b["registered"]:
                    findings.append((3, f"link text shows {a['registered']} but goes to {b['registered']}"))
        return findings


class SenderAddressRule(Rule):
    name = "sender_address"

    def analyze(self, email):
        findings = []
        name, addr, domain = parse_sender(email.get("from"))
        if not domain:
            return [(2, "sender address is missing or malformed")]
        d = split_domain(domain)
        if d["registered"] in config.BLOCKLIST_DOMAINS:
            findings.append((3, f"sender domain {domain} is on the blocklist"))
        look = brand_lookalike(domain)
        if look:
            findings.append(look)
        if d["suffix"].split(".")[-1] in config.SUSPICIOUS_TLDS:
            findings.append((1, f"sender uses suspicious TLD .{d['suffix']}"))
        if "xn--" in domain or any(ord(c) > 127 for c in domain):
            findings.append((3, "sender domain uses punycode/unicode characters"))
        # Display name claims to be a brand, but the domain isn't theirs
        shown = " ".join(deobfuscate(name))
        for brand, legit in config.BRANDS.items():
            if brand in shown and d["registered"] not in legit:
                findings.append((3, f"display name says '{brand}' but email comes from {domain}"))
                break
        reply_to = email.get("reply_to")
        if reply_to:
            rd = split_domain(parse_sender(reply_to)[2])["registered"]
            if rd and rd != d["registered"]:
                findings.append((2, f"Reply-To domain ({rd}) differs from sender domain"))
        return findings


class UrgentLanguageRule(Rule):
    name = "urgent_language"

    def analyze(self, email):
        subject, body = clean_text(email.get("subject")), clean_text(email.get("body"))
        findings = []
        variants = deobfuscate(subject + " . " + body)
        for pattern, points, label in config.URGENT_PATTERNS:
            if any(re.search(pattern, v) for v in variants):
                findings.append((points, label))
        letters = [c for c in subject if c.isalpha()]
        if len(letters) >= 6 and sum(c.isupper() for c in letters) / len(letters) > 0.7:
            findings.append((1, "subject is mostly ALL CAPS"))
        if (subject + body).count("!") >= 3:
            findings.append((1, "excessive exclamation marks"))
        return findings


def _candidate_hosts(email):
    """Hosts of every URL in the body (plus the sender's domain) - what the feed/ML rules inspect."""
    hosts = [get_host(u)[0] for u in extract_urls(email.get("body") or "")]
    for href, _ in extract_anchors(email.get("body") or ""):
        hosts.append(get_host(href)[0])
    sender_domain = parse_sender(email.get("from"))[2]
    if sender_domain:
        hosts.append(sender_domain)
    return list(dict.fromkeys(h for h in hosts if h))


class KnownPhishingFeedRule(Rule):
    """Looks every link/sender domain up in the open-source phishing feeds (parents included)."""
    name = "known_phishing_feed"

    def analyze(self, email):
        db = feeds.get_db()
        if not db.loaded:
            return []
        findings = []
        for host in _candidate_hosts(email):
            hit = db.lookup(host)
            if hit:
                where = host if hit == host else f"{host} (parent domain {hit})"
                findings.append((5, f"{where} is listed in an open phishing feed"))
        return findings[:3]


class MLDomainRule(Rule):
    """Trained classifier on domain/URL structure. Only confident predictions earn points."""
    name = "ml_url_classifier"

    def analyze(self, email):
        if not ml.available():
            return []
        db, best = feeds.get_db(), (0.0, None)
        for host in _candidate_hosts(email):
            d = split_domain(host)["registered"]
            if db.is_legit(host) or any(d in legit for legit in config.BRANDS.values()):
                continue  # known-good domains are never scored
            p = ml.predict_proba(host)
            if p is not None and p > best[0]:
                best = (p, host)
        p, host = best
        points = 3 if p >= 0.98 else 2 if p >= 0.95 else 1 if p >= 0.90 else 0
        return [(points, f"ML model rates '{host}' as {p:.0%} likely phishing")] if points else []
