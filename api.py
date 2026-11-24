"""
POST /check          {"url": "https://adcb-secure.xyz/login"}
POST /check-number   {"number": "+971551234567", "brand_context": "ADCB"}
"""
from datetime import datetime, timezone
from urllib.parse import urlparse

import joblib, pandas as pd, phonenumbers
from fastapi import FastAPI
from pydantic import BaseModel
from phonenumbers import PhoneNumberType as T

from features import string_feats, reg_of

ESCALATE, BLOCK = 0.30, 0.85

bundle = joblib.load("data/model.pkl")
MODEL, FEATS = bundle["model"], bundle["features"]

TEXT = {
    "free_host":    "Hosted on a free platform that issues instant HTTPS",
    "cheap_tld":    "Uses a cheap TLD commonly bought in bulk by scammers",
    "n_hyphens":    "Domain name padded with hyphens",
    "dom_len":      "Unusually long domain name",
    "entropy":      "Domain name looks randomly generated",
    "n_digits":     "Digits inserted into the domain name",
    "digit_ratio":  "High proportion of digits in the domain",
    "brand_in_dom": "Contains a protected brand name",
    "ct_free_ca":   "Certificate issued by a free authority",
    "ct_age_bucket":"Domain certificate issued very recently",
    "ct_max_san":   "Certificate covers many unrelated domains (bulk issuance)",
    "ct_found":     "No certificate history found",
}
RULE_TEXT = {
    "_rule_brand_misplaced": "Brand name appears in the subdomain but the real domain is different",
    "_rule_kw_in_sub":       "Security words used in the subdomain",
    "_rule_deep_sub":        "Unusually deep subdomain nesting",
}

app = FastAPI(title="scam-detect")

from fastapi.middleware.cors import CORSMiddleware   # Task 5: lets clients/check.html (file://) call the API
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class UrlIn(BaseModel):
    url: str

class NumIn(BaseModel):
    number: str
    brand_context: str | None = None

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

@app.post("/check")
def check(body: UrlIn):
    raw = body.url.strip()
    host = (urlparse(raw).hostname if "://" in raw else raw.split("/")[0]) or raw
    host = host.lower().strip(".")

    f = string_feats(host)
    rules = {k: v for k, v in f.items() if k.startswith("_rule")}
    row = {k: v for k, v in f.items() if not k.startswith("_rule")}

    for c in FEATS:                       # CT fields filled by Tier 2 later
        row.setdefault(c, -1 if c == "ct_age_bucket" else 0)

    X = pd.DataFrame([row])[FEATS]
    score = float(MODEL.predict_proba(X)[0, 1])

    reasons = []
    for name, w in sorted(zip(FEATS, MODEL.feature_importances_),
                          key=lambda kv: -kv[1]):
        if row.get(name) and name in TEXT:
            reasons.append({"code": name, "direction": "risk", "text": TEXT[name]})
        if len(reasons) == 4:
            break
    for k, v in rules.items():
        if v:
            reasons.insert(0, {"code": k, "direction": "risk", "text": RULE_TEXT[k]})

    hard = any(rules.values())
    verdict = ("malicious" if score >= BLOCK or hard
               else "suspicious" if score >= ESCALATE
               else "clean")

    return {"url": raw, "host": host, "reg_domain": reg_of(host),
            "verdict": verdict, "score": round(score * 100),
            "reasons": reasons[:5], "brand_match": None,
            "needs_tier2": ESCALATE <= score < BLOCK,
            "checked_at": now()}

import csv, pathlib

OFFICIAL, BRAND_NUMBERS = set(), {}
_hl = pathlib.Path("data/helplines.csv")
if _hl.exists():
    for row in csv.DictReader(_hl.read_text("utf-8").splitlines()):
        num = (row.get("number") or "").strip()
        if num:
            OFFICIAL.add(num)
            BRAND_NUMBERS.setdefault(row["brand"].lower(), set()).add(num)
print(f"loaded {len(OFFICIAL)} official numbers")

@app.post("/check-number")
def check_number(body: NumIn):
    reasons, score = [], 0
    try:
        n = phonenumbers.parse(body.number, "AE")
    except Exception:
        return {"number": body.number, "verdict": "unknown", "score": 0,
                "reasons": [{"code": "unparseable", "direction": "risk",
                             "text": "Not a valid phone number"}],
                "checked_at": now()}

    e164 = phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)
    if e164 in OFFICIAL:
        return {"number": e164, "verdict": "clean", "score": 0,
                "reasons": [{"code": "official", "direction": "safe",
                             "text": "Matches the brand's published helpline"}],
                "checked_at": now()}

    kind = phonenumbers.number_type(n)
    if kind == T.MOBILE:
        score += 70
        reasons.append({"code": "mobile_prefix", "direction": "risk",
                        "text": "Personal mobile number — UAE banks, couriers and "
                                "government bodies publish toll-free or landline numbers"})
    elif kind in (T.TOLL_FREE, T.FIXED_LINE, T.VOIP):
        reasons.append({"code": "line_type", "direction": "safe",
                        "text": "Toll-free or landline, consistent with a real helpline"})

    if body.brand_context and OFFICIAL:
        score += 25
        reasons.append({"code": "not_in_official_set", "direction": "risk",
                        "text": f"Not among {body.brand_context}'s published numbers"})

    return {"number": e164,
            "verdict": "malicious" if score >= 85 else
                       "suspicious" if score >= 40 else "clean",
            "score": min(score, 100), "reasons": reasons, "checked_at": now()}