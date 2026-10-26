"""Open-source phishing feeds: download, cache, and look up (with parent-domain traversal).

    python -m detector.feeds update    # download/refresh feeds into data/
    python -m detector.feeds status    # show what is loaded
    python -m detector.feeds check evil.login.example.com
"""
import gzip
import os
import re
import sys
import time
import urllib.request

from .utils import split_domain

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
PHISH_FILE = os.path.join(DATA_DIR, "phishing_domains.txt.gz")
LEGIT_FILE = os.path.join(DATA_DIR, "legit_domains.txt.gz")

# (name, url, kind) - kind is "domains" (one host per line) or "urls" (one URL per line).
PHISHING_SOURCES = [
    ("Phishing.Database",
     "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
     "domains"),
    ("OpenPhish", "https://openphish.com/feed.txt", "urls"),  # optional, skipped if unreachable
]
LEGIT_SOURCES = [
    ("OpenDNS top domains",
     "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt",
     "domains"),
]
# Add more here, e.g. a PhishTank / URLhaus export you downloaded, or any domain-per-line list.

_HOST_RE = re.compile(r"^[a-z0-9._-]+$")


def normalize_host(line, kind="domains"):
    line = line.strip().lower()
    if not line or line.startswith("#"):
        return None
    if kind == "urls" or "://" in line:
        line = line.split("://", 1)[-1]
    line = line.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    line = line.rsplit("@", 1)[-1].split(":", 1)[0].strip(".")
    return line if line and _HOST_RE.match(line) and "." in line else None


def _download(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": "phishing-email-detector/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")


def _fetch_all(sources):
    hosts, report = set(), {}
    for name, url, kind in sources:
        try:
            before = len(hosts)
            for line in _download(url).splitlines():
                h = normalize_host(line, kind)
                if h:
                    hosts.add(h)
            report[name] = len(hosts) - before
        except Exception as exc:  # network errors must not break the app
            report[name] = f"FAILED ({exc})"
    return hosts, report


def _write(path, hosts):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = path + ".tmp"
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        f.write("\n".join(sorted(hosts)))
    os.replace(tmp, path)


def update():
    """Download all sources and rewrite the cache. Returns a report dict."""
    global _db
    report = {}
    phish, report["phishing"] = _fetch_all(PHISHING_SOURCES)
    if phish:
        _write(PHISH_FILE, phish)
    legit, report["legit"] = _fetch_all(LEGIT_SOURCES)
    if legit:
        _write(LEGIT_FILE, legit)
    _db = None  # force reload
    return report


def _read(path):
    if not os.path.exists(path):
        return set()
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return {l for l in f.read().splitlines() if l}


class FeedDB:
    def __init__(self):
        self.phishing = _read(PHISH_FILE)
        self.legit = _read(LEGIT_FILE)
        self.loaded = bool(self.phishing)
        self.updated = os.path.getmtime(PHISH_FILE) if os.path.exists(PHISH_FILE) else None

    def lookup(self, host):
        """Walk a.b.evil.com -> b.evil.com -> evil.com; return the listed entry, else None."""
        host = (host or "").lower().strip(".")
        labels = host.split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in self.phishing:
                # a popular legit domain listed as a whole (abused/compromised) is
                # ignored; a listed *subpath host* on it (e.g. evil.sites.google.com) still counts.
                if candidate in self.legit:
                    return None
                return candidate
        return None

    def is_legit(self, host):
        return split_domain(host)["registered"] in self.legit

    def status(self):
        age = None if not self.updated else round((time.time() - self.updated) / 86400, 1)
        return {"loaded": self.loaded, "phishing_entries": len(self.phishing),
                "legit_entries": len(self.legit), "age_days": age}


_db = None


def get_db():
    global _db
    if _db is None:
        _db = FeedDB()
    return _db


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "update":
        for k, v in update().items():
            print(k, v)
    elif cmd == "check" and len(sys.argv) > 2:
        print(get_db().lookup(sys.argv[2]) or "not listed")
    else:
        print(get_db().status())
