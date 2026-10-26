"""Lightweight ML URL/domain classifier.

Training happens offline (train_model.py, uses scikit-learn). The trained logistic-regression
weights are saved to data/model.json, and prediction here is pure Python, so the deployed
app needs no numpy/sklearn (important for small serverless deployments such as Vercel).
"""
import json
import math
import os
import re
import zlib

from . import config
from .lookalike import brand_lookalike
from .utils import split_domain

MODEL_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "model.json")
HASH_DIM = 8192
KEYWORDS = ("login", "signin", "secure", "verify", "account", "update", "bank", "confirm", "wallet",
            "webmail", "support", "billing", "password", "auth", "alert", "recover", "unlock", "invoice")
NUMERIC = ["len_host", "len_label", "dots", "hyphens", "digits", "digit_ratio", "entropy", "depth",
           "is_ip", "bad_tld", "keywords", "lookalike", "brand_in_host", "longest_digit_run",
           "punycode", "vowel_ratio"]
N_NUM = len(NUMERIC)
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _entropy(s):
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def featurize(host):
    """host -> sparse feature dict {index: value}. Must stay identical between training and inference."""
    host = (host or "").lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    d = split_domain(host)
    label = d["label"]
    letters = [c for c in label if c.isalpha()]
    digit_runs = re.findall(r"\d+", label)
    f = [
        len(host) / 50, len(label) / 25, host.count(".") / 5, host.count("-") / 4,
        sum(c.isdigit() for c in host) / 10, sum(c.isdigit() for c in label) / max(len(label), 1),
        _entropy(label) / 4.5, (len(d["sub"].split(".")) if d["sub"] else 0) / 4,
        1.0 if IP_RE.match(host) else 0.0,
        1.0 if d["suffix"].split(".")[-1] in config.SUSPICIOUS_TLDS else 0.0,
        sum(k in host for k in KEYWORDS) / 3,
        1.0 if brand_lookalike(host) else 0.0,
        1.0 if any(b in host for b in config.BRANDS) and not any(
            d["registered"] in legit for legit in config.BRANDS.values()) else 0.0,
        (max(map(len, digit_runs)) if digit_runs else 0) / 8,
        1.0 if "xn--" in host else 0.0,
        (sum(c in "aeiou" for c in letters) / len(letters)) if letters else 0.0,
    ]
    feats = {i: v for i, v in enumerate(f) if v}
    padded = "^" + host + "$"
    buckets = []
    for n in (2, 3, 4):                                    # character n-grams
        buckets += [f"{n}:{padded[i:i + n]}" for i in range(len(padded) - n + 1)]
    buckets += ["t:" + t for t in re.split(r"[.\-_]", host) if t]   # word tokens
    for g in buckets:
        idx = N_NUM + zlib.crc32(g.encode()) % HASH_DIM
        feats[idx] = feats.get(idx, 0.0) + 1.0 / math.sqrt(len(buckets))
    return feats


_model = None


def load_model():
    global _model
    if _model is None:
        try:
            with open(MODEL_FILE, encoding="utf-8") as f:
                _model = json.load(f)
        except (OSError, ValueError):
            _model = {}
    return _model


def available():
    return bool(load_model())


def predict_proba(host):
    """Probability (0-1) that `host` is a phishing domain, or None if no model is installed."""
    m = load_model()
    if not m:
        return None
    w = m["weights"]
    z = m["bias"] + sum(w[i] * v for i, v in featurize(host).items())
    return 1 / (1 + math.exp(-max(min(z, 30), -30)))
