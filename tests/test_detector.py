import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from detector.rule_factory import RuleFactory
from detector.analyzer import analyze_email

def links(body): return RuleFactory.get_rule("suspicious_links").check({"body": body})
def sender(s): return RuleFactory.get_rule("sender_address").check({"from": s})
def urgent(sub, body=""): return RuleFactory.get_rule("urgent_language").check({"subject": sub, "body": body})

def test_leet_domain():        assert links("go to http://Amaz0n.com/login")
def test_typosquat():          assert links("https://www.arnazon.com")  # rn -> m
def test_paypal_1():           assert links("https://paypa1.com/verify")
def test_brand_keyword():      assert links("https://amazon-security.com")
def test_brand_in_subdomain(): assert links("https://paypal.com.evil.net/login")
def test_ip_link():            assert links("http://192.168.4.5/login")
def test_punycode():           assert links("http://xn--pypal-4ve.com")
def test_blocklist():          assert links("http://phishing.com/verify")
def test_html_mismatch():      assert links('<a href="http://evil.xyz">https://www.paypal.com</a>')
def test_legit_links():
    assert not links("https://www.amazon.in/gp/help and https://accounts.google.com")
def test_sender_spoof():       assert sender("Amazon <help@amaz0n.com>")
def test_display_name():       assert sender("PayPal Support <x@random-mail.com>")
def test_legit_sender():       assert not sender("Amazon <order@amazon.com>")
def test_urgent_leet():        assert urgent("URG3NT: V3rify your account")
def test_calm_email():         assert not urgent("Lunch?", "Want to grab lunch tomorrow?")
def test_overall():
    assert analyze_email({"from": "a@amaz0n.com", "subject": "Urgent", "body": "verify http://amaz0n.com"})["verdict"] == "Phishing"


# ---------- open feed + ML tests (skipped automatically if data files are missing) ----------
import pytest
from detector import feeds, ml

needs_feed = pytest.mark.skipif(not feeds.get_db().loaded, reason="run: python -m detector.feeds update")
needs_model = pytest.mark.skipif(not ml.available(), reason="run: python train_model.py")

def feed_rule(body): return RuleFactory.get_rule("known_phishing_feed").check({"from": "a@gmail.com", "body": body})

@needs_feed
def test_feed_exact_and_parent_traversal():
    db = feeds.get_db()
    host = next(h for h in sorted(db.phishing) if h.count(".") == 1 and h not in db.legit)
    assert feed_rule(f"http://{host}/x")
    assert feed_rule(f"http://a.b.c.{host}/x")           # parent-domain traversal

@needs_feed
def test_feed_ignores_legit_domains():
    assert not feed_rule("https://www.google.com and https://mercadolibre.com.ar")

@needs_feed
def test_feed_hit_is_phishing_verdict():
    host = next(h for h in sorted(feeds.get_db().phishing) if h.count(".") == 1 and h not in feeds.get_db().legit)
    assert analyze_email({"from": "x@gmail.com", "subject": "hi", "body": f"http://{host}"})["verdict"] == "Phishing"

@needs_model
def test_ml_scores_random_domain_high_and_legit_low():
    assert ml.predict_proba("x8f2k9qpzw7v.top") > 0.9
    assert ml.predict_proba("www.google.com") < 0.2
    assert not RuleFactory.get_rule("ml_url_classifier").check({"from": "a@amazon.in", "body": "https://www.amazon.in"})
