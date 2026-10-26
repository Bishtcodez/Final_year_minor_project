## Detection engine (v2)

Files: `detector/config.py` (all lists), `detector/utils.py`, `detector/rules.py`, `detector/rule_factory.py`, `detector/analyzer.py`.

Instead of matching fixed words, each rule awards **points** with a **reason**:

| Rule | What it catches |
|---|---|
| `suspicious_links` | look-alike domains (`amaz0n.com`, `paypa1.com`, `arnazon.com`), brand names stuffed into other domains (`amazon-security.com`, `paypal.com.evil.net`), raw IP links, punycode/homograph domains, `@` tricks, URL shorteners, suspicious TLDs, plain `http`, HTML links whose text and href disagree, blocklist |
| `sender_address` | spoofed/look-alike sender domain, display name claiming a brand (`"PayPal" <x@random.com>`), Reply-To mismatch, malformed sender |
| `urgent_language` | weighted phrases ("verify your account", "within 24 hours", "account suspended", asks for OTP/PIN), obfuscation like `URG3NT`, ALL-CAPS subjects, zero-width characters |

How look-alikes are found: the domain label is de-obfuscated (`0→o`, `1→l/i`, `3→e`, `rn→m` ...) and compared to a brand list; Levenshtein edit distance catches typos. Real brand domains in `BRANDS` are whitelisted.

Verdicts: **Phishing** (score >= 7 or 2+ rules flagged), **Suspicious** (>= 2), otherwise **No known indicator detected** (not a guarantee of safety).

API: `POST /detect` -> `{rule: bool}` (unchanged), `POST /analyze` -> `{verdict, total_score, rules:{...reasons}}`.

Tests: `pip install pytest && pytest tests`

## Open-source phishing feeds + ML (v3)

**Feeds** (`detector/feeds.py`)
- Downloads *Phishing.Database* (~390k active phishing domains, GitHub) and, if reachable, *OpenPhish*. Cached in `data/` (gzip).
- Every link host, HTML href and the sender domain is looked up with **parent-domain traversal**:
  `login.secure.evil.com -> secure.evil.com -> evil.com`. A listed parent flags all its subdomains.
- Popular legit domains (OpenDNS top 10k) are never flagged by a whole-domain listing (avoids hits on abused/compromised big sites).
- Refresh: `python -m detector.feeds update` (run daily/weekly). Check one host: `python -m detector.feeds check some.host.com`.
- Add your own sources (PhishTank export, URLhaus, ...) in `PHISHING_SOURCES`.

**ML classifier** (`detector/ml.py`, `train_model.py`)
- Logistic regression over domain features (length, digits, entropy, hyphens, keywords, look-alike flag, char 2-4-grams, word tokens).
- Train: `pip install -r requirements-dev.txt && python train_model.py` -> writes `data/model.json`.
- Inference is pure Python (no sklearn needed in production).
- Held-out results (split by domain): AUC 0.967. At the thresholds used (>=0.95): ~99.5% precision, ~61% recall, ~0.7% FPR.
- Only confident predictions earn points (>=0.90: 1, >=0.95: 2, >=0.98: 3). ML is a supporting signal, never the only proof.

**Verdict:** a feed hit alone => *Phishing*. Endpoints: `/analyze` (reasons), `/detect` (bool dict), `/status` (feed size/age, model metrics).

**Limitations (say these in your report):** feeds only know *already reported* domains (new/zero-day phishing is missed - that's what the look-alike rules and ML are for); the model is trained on popular legit domains vs. phishing, so unfamiliar-but-benign small sites can score high (hence the strict thresholds); on Vercel the filesystem is read-only, so refresh feeds locally and redeploy.
