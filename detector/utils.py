import re
from email.utils import parseaddr
from urllib.parse import urlparse
from .config import MULTI_PART_TLDS

URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"')\]]+)""")
ANCHOR_RE = re.compile(r"""(?is)<a\s[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>""")
ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)

_LEET_BASE = {"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a", "8": "b"}
_LEET_L = str.maketrans({**_LEET_BASE, "1": "l", "!": "l"})
_LEET_I = str.maketrans({**_LEET_BASE, "1": "i", "!": "i"})


def clean_text(text):
    return (text or "").translate(ZERO_WIDTH)


def deobfuscate(text):
    """Return variants of text with look-alike characters replaced (0->o, 1->l/i, rn->m ...).
    Only words that contain real letters are converted, so plain numbers like '24' stay intact."""
    text = clean_text(text).lower()
    out = set()
    for table in (_LEET_L, _LEET_I):
        def fix(m, table=table):
            w = m.group(0)
            return w.translate(table).replace("rn", "m").replace("vv", "w") if sum(c.isalpha() for c in w) >= 2 else w
        out.add(re.sub(r"\S+", fix, text))
    return out


def levenshtein(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def split_domain(host):
    """'login.amaz0n-secure.co.uk' -> dict(sub='login', label='amaz0n-secure', suffix='co.uk', registered='amaz0n-secure.co.uk')"""
    host = (host or "").lower().strip(".")
    labels = host.split(".")
    if len(labels) < 2:
        return {"host": host, "sub": "", "label": host, "suffix": "", "registered": host}
    n = 3 if ".".join(labels[-2:]) in MULTI_PART_TLDS and len(labels) >= 3 else 2
    reg = labels[-n:]
    return {
        "host": host,
        "sub": ".".join(labels[:-n]),
        "label": reg[0],
        "suffix": ".".join(reg[1:]),
        "registered": ".".join(reg),
    }


def get_host(url):
    try:
        if not re.match(r"(?i)^https?://", url):
            url = "http://" + url
        return urlparse(url).hostname or "", url
    except ValueError:
        return "", url


def extract_urls(text):
    urls = [u.rstrip(".,;:!?") for u in URL_RE.findall(clean_text(text))]
    return list(dict.fromkeys(urls))


def extract_anchors(html):
    return ANCHOR_RE.findall(clean_text(html))


def parse_sender(sender):
    name, addr = parseaddr(sender or "")
    addr = addr.lower()
    domain = addr.rsplit("@", 1)[1] if "@" in addr else ""
    return name, addr, domain
