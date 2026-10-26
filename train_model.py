"""Train the ML domain classifier from the open feeds.

    pip install scikit-learn numpy scipy
    python -m detector.feeds update      # (once) download feeds
    python train_model.py

Positives = hosts from the open phishing feed. Negatives = popular legit domains (OpenDNS top 10k),
plus common subdomain variants (www., login., secure. ...) so the model can't learn
"has a subdomain => phishing". Train/test split is by registered domain to avoid leakage.
"""
import json, random, time, zlib
from collections import defaultdict

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score, roc_auc_score, confusion_matrix

from detector import feeds, ml
from detector.utils import split_domain

random.seed(7)
MAX_PER_DOMAIN, MAX_POS = 10, 60000
SUBS = ["www", "mail", "login", "accounts", "support", "secure", "my", "app", "blog", "m", "account", "portal"]

db = feeds.get_db()
assert db.loaded, "run: python -m detector.feeds update"

# ---- positives: cap per registered domain so free-hosting providers don't dominate
by_dom = defaultdict(list)
for h in db.phishing:
    by_dom[split_domain(h)["registered"]].append(h)
pos = []
for dom, hosts in by_dom.items():
    random.shuffle(hosts)
    pos += hosts[:MAX_PER_DOMAIN]
random.shuffle(pos)
pos = pos[:MAX_POS]

# ---- negatives: legit domains + subdomain variants
neg = []
for d in db.legit:
    neg.append(d)
    for s in random.sample(SUBS, 2):
        neg.append(f"{s}.{d}")

data = [(h, 1) for h in pos] + [(h, 0) for h in neg]
is_test = lambda h: zlib.crc32(split_domain(h)["registered"].encode()) % 5 == 0
train = [x for x in data if not is_test(x[0])]
test = [x for x in data if is_test(x[0])]
print(f"train={len(train)} test={len(test)}  (pos={len(pos)}, neg={len(neg)})")


def matrix(rows):
    indptr, indices, vals = [0], [], []
    for h, _ in rows:
        for i, v in ml.featurize(h).items():
            indices.append(i); vals.append(v)
        indptr.append(len(indices))
    return csr_matrix((vals, indices, indptr), shape=(len(rows), ml.N_NUM + ml.HASH_DIM)), np.array([y for _, y in rows])

Xtr, ytr = matrix(train)
Xte, yte = matrix(test)
clf = LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced")
clf.fit(Xtr, ytr)

p = clf.predict_proba(Xte)[:, 1]
pred = p >= 0.5
tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
metrics = {"test_size": len(test), "precision": round(precision_score(yte, pred), 4),
           "recall": round(recall_score(yte, pred), 4), "auc": round(roc_auc_score(yte, p), 4),
           "false_positive_rate": round(float(fp / (fp + tn)), 4)}
print(metrics)
for thr in (0.7, 0.85, 0.95, 0.98):
    q = p >= thr
    print(f"  thr={thr}: precision={precision_score(yte, q):.3f} recall={recall_score(yte, q):.3f} FPR={((q) & (yte == 0)).sum() / (yte == 0).sum():.3f}")

w = clf.coef_[0]
json.dump({"bias": round(float(clf.intercept_[0]), 5), "weights": [round(float(x), 4) for x in w],
           "metrics": metrics, "trained": time.strftime("%Y-%m-%d"),
           "n_train": len(train)}, open(ml.MODEL_FILE, "w"))
print("saved", ml.MODEL_FILE)
