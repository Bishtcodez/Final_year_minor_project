from detector.analyzer import analyze_email

SAMPLES = [
    {"from": "phisher@example.com", "subject": "Urgent: Verify Your Account",
     "body": "Please click the link to verify your account: http://phishing.com/verify"},
    {"from": "Amazon Support <support@amaz0n-security.com>", "subject": "Your order is on hold",
     "body": "Confirm your payment within 24 hours: https://www.amaz0n.com/login"},
    {"from": "PayPal <service@paypa1.com>", "subject": "Account limited",
     "body": "Your account has been limited. Login: http://paypal.com.secure-check.xyz/login"},
    {"from": "friend@gmail.com", "subject": "Lunch tomorrow?",
     "body": "Hey, want to grab lunch? Menu: https://www.amazon.in/gp/help"},
]

if __name__ == "__main__":
    for e in SAMPLES:
        r = analyze_email(e)
        print(f"\n[{r['verdict']}] score={r['total_score']}  from={e['from']}")
        for rule, d in r["rules"].items():
            for reason in d["reasons"]:
                print(f"   - ({rule}) {reason}")
