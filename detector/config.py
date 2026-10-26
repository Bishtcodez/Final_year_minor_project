"""All tunable data lives here. Edit these lists to change detection."""

# Brand keyword -> legitimate registered domains for that brand.
BRANDS = {
    "amazon":    {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com"},
    "paypal":    {"paypal.com", "paypal.me"},
    "google":    {"google.com", "gmail.com", "googlemail.com", "youtube.com"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com", "microsoftonline.com"},
    "apple":     {"apple.com", "icloud.com"},
    "facebook":  {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "netflix":   {"netflix.com"},
    "linkedin":  {"linkedin.com"},
    "whatsapp":  {"whatsapp.com"},
    "flipkart":  {"flipkart.com"},
    "paytm":     {"paytm.com"},
    "sbi":       {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"},
    "hdfcbank":  {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "dropbox":   {"dropbox.com"},
    "github":    {"github.com"},
}

# Domains you want to flag no matter what (the original project's behaviour).
BLOCKLIST_DOMAINS = {"phishing.com", "malicious.com"}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work",
    "zip", "mov", "support", "country", "loan", "win", "icu", "buzz", "rest",
}

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
                  "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"}

FREE_EMAIL_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
                      "proton.me", "protonmail.com", "aol.com", "rediffmail.com"}

# Two-part public suffixes so "evil.co.uk" is parsed correctly.
MULTI_PART_TLDS = {"co.uk", "co.in", "com.au", "co.jp", "com.br", "org.uk", "gov.in", "ac.in", "net.in",
                   "com.ar", "com.mx", "com.tr", "co.za", "com.cn", "co.kr", "co.nz", "com.sg", "com.pk",
                   "com.ng", "co.id", "com.my", "com.ph", "com.vn", "com.hk", "com.tw", "co.th", "com.eg",
                   "com.sa", "com.ua", "org.in", "org.au", "net.au", "me.uk", "ne.jp", "or.jp"}

# (regex, points, description) - matched against lower-cased, de-obfuscated text.
URGENT_PATTERNS = [
    (r"\burgent(ly)?\b|\bimmediate(ly)?\b|\basap\b|\bright away\b", 1, "urgency words"),
    (r"verify (your|ur) (account|identity|email|details|information)", 2, "asks to verify account"),
    (r"(account|card|access).{0,25}(suspended|locked|limited|disabled|closed|compromised|restricted)", 2, "threatens account suspension"),
    (r"within \d+ ?(hours?|hrs?|days?|minutes?)|\b24 ?hours?\b|\b48 ?hours?\b", 2, "deadline pressure"),
    (r"click (the )?(link|here|below)|follow (the|this) link", 1, "asks to click a link"),
    (r"confirm (your )?(password|identity|details|payment|login|credentials|bank)", 2, "asks to confirm credentials"),
    (r"(update|verify|confirm) (your )?(billing|payment|card|banking)", 2, "asks to update payment info"),
    (r"unusual|suspicious|unauthori[sz]ed|security alert", 1, "security scare wording"),
    (r"password.{0,20}(expire|expiring|expired)", 2, "password expiry scare"),
    (r"final notice|last warning|last chance|failure to (comply|respond)", 2, "threat/final warning"),
    (r"you('ve| have)? (won|been selected)|lottery|prize|claim your (reward|gift)", 2, "prize/reward bait"),
    (r"\bact now\b|\blimited time\b", 1, "pressure phrase"),
    (r"(send|share|enter).{0,20}(otp|pin|cvv|password|ssn)", 3, "asks for secret codes"),
    (r"gift ?cards?", 1, "gift card request"),
]
