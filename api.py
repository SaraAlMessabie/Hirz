"""
POST /check          {"url": "...", "deep": true}
POST /check-number   {"number": "+971...", "brand_context": "ADCB"}
GET  /blocklist  /detections  /stats  /campaigns
"""
import csv, pathlib
from datetime import datetime, timezone
from urllib.parse import urlparse

import joblib, pandas as pd, phonenumbers
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from phonenumbers import PhoneNumberType as T

from features import string_feats, reg_of, FREE_HOSTS
from tier2 import rdap_features, tls_facts, page_facts
from llm_check import evidence_packet, llm_check

ESCALATE, BLOCK = 0.30, 0.80
SIM_HARD, SIM_SOFT = 0.60, 0.40

bundle = joblib.load("data/model.pkl")
MODEL, FEATS = bundle["model"], bundle["features"]

TEXT = {
    "free_host":    "Hosted on a free platform that issues instant HTTPS",
    "cheap_tld":    "Uses a cheap TLD commonly bought in bulk by scammers",
    "n_hyphens":    "Domain name padded with hyphens",
    "dom_len":      "Unusually long domain name",
    "n_digits":     "Digits inserted into the domain name",
    "digit_ratio":  "High proportion of digits in the domain",
    "brand_in_dom": "Contains a protected brand name",
    "is_punycode":  "Domain uses look-alike characters from another alphabet",
}
RULE_TEXT = {
    "_rule_brand_misplaced": "Brand name appears in the subdomain but the real domain is different",
    "_rule_kw_in_sub":       "Security words used in the subdomain",
    "_rule_deep_sub":        "Unusually deep subdomain nesting",
}

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _rows(path):
    p = pathlib.Path(path)
    if not p.exists():
        return []
    return list(csv.DictReader(p.read_text("utf-8", errors="ignore").splitlines()))

# ---------------------------------------------------------------- blocklist
BLOCK_FILE = pathlib.Path("data/blocklist.csv")
BLOCKLIST = {}

def load_blocklist():
    BLOCKLIST.clear()
    for row in _rows("data/blocklist.csv"):
        if row.get("domain"):
            BLOCKLIST[row["domain"]] = row
    for path, src in (("data/ct_hits.csv", "ct_watch"),
                      ("data/lookalikes_triaged.csv", "permutation_sweep")):
        for row in _rows(path):
            d = (row.get("domain") or "").strip()
            if not d or d in BLOCKLIST:
                continue
            try:
                sc = float(row.get("score") or 0)
            except ValueError:
                sc = 0
            if sc >= 80:
                BLOCKLIST[d] = {"domain": d, "source": src, "score": sc,
                                "first_seen": row.get("first_seen_by_us", "")}
    print(f"blocklist: {len(BLOCKLIST)} domains")

def remember(domain, source, score):
    if not domain or domain in BLOCKLIST:
        return
    rec = {"domain": domain, "source": source, "score": score, "first_seen": now()}
    BLOCKLIST[domain] = rec
    fresh = not BLOCK_FILE.exists()
    with BLOCK_FILE.open("a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if fresh:
            w.writerow(["domain", "source", "score", "first_seen"])
        w.writerow([domain, source, score, rec["first_seen"]])

load_blocklist()

# ---------------------------------------------------------------- helplines
OFFICIAL, BRAND_NUMBERS = set(), {}
for row in _rows("data/helplines.csv"):
    num = (row.get("number") or "").strip()
    if num:
        OFFICIAL.add(num)
        BRAND_NUMBERS.setdefault((row.get("brand") or "").lower(), set()).add(num)
print(f"helplines: {len(OFFICIAL)} official numbers")

# ---------------------------------------------------------------- app
app = FastAPI(title="scam-detect")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

class UrlIn(BaseModel):
    url: str
    deep: bool = True

class NumIn(BaseModel):
    number: str
    brand_context: str | None = None

@app.get("/")
def root():
    return {"service": "scam-detect", "status": "ok",
            "endpoints": ["POST /check", "POST /check-number",
                          "GET /detections", "GET /stats",
                          "GET /campaigns", "GET /blocklist"],
            "docs": "/docs", "features": len(FEATS),
            "blocklist_size": len(BLOCKLIST),
            "official_numbers": len(OFFICIAL),
            "thresholds": {"escalate": ESCALATE, "block": BLOCK}}

# ---------------------------------------------------------------- dashboard
@app.get("/stats")
def stats():
    ct = _rows("data/ct_hits.csv")
    lk = _rows("data/lookalikes_triaged.csv")
    by_brand = {}
    for r in ct:
        b = r.get("brand") or "?"
        by_brand[b] = by_brand.get(b, 0) + 1
    unknown = sum(1 for r in ct if str(r.get("already_in_public_feed")) == "0")
    recent = [r for r in lk
              if str(r.get("age_bucket", "")).strip() in ("0", "1", "2", "3")]
    mx = sum(1 for r in recent if str(r.get("has_mx")) == "1")
    return {"ct_discoveries": len(ct),
            "unknown_to_public_feeds": unknown,
            "permutation_total": len(lk),
            "permutation_recent": len(recent),
            "permutation_with_mx": mx,
            "blocklist_size": len(BLOCKLIST),
            "by_brand": dict(sorted(by_brand.items(), key=lambda kv: -kv[1])[:10])}

@app.get("/detections")
def detections(limit: int = 200, brand: str = None, min_score: int = 0,
               source: str = None):
    out = []
    for path, src in (("data/ct_hits.csv", "certificate_transparency"),
                      ("data/lookalikes_triaged.csv", "permutation_sweep")):
        if source and source != src:
            continue
        for r in _rows(path):
            try:
                sc = float(r.get("score") or 0)
            except ValueError:
                sc = 0
            if sc < min_score:
                continue
            if brand and brand.lower() not in (r.get("brand") or "").lower():
                continue
            out.append({
                "domain": r.get("domain"),
                "brand": (r.get("brand") or "").replace(".com", "").replace(".ae", ""),
                "score": sc,
                "verdict": r.get("verdict") or "",
                "source": src,
                "first_seen": r.get("first_seen_by_us") or r.get("cert_issued") or "",
                "in_public_feed": r.get("already_in_public_feed"),
                "free_ca": r.get("free_ca"),
                "has_mx": r.get("has_mx"),
                "age_bucket": r.get("age_bucket"),
            })
    out.sort(key=lambda x: x["score"], reverse=True)
    return {"total": len(out), "showing": min(limit, len(out)), "items": out[:limit]}

@app.get("/campaigns")
def campaigns(limit: int = 50):
    rows = _rows("data/campaigns.csv")
    pred = _rows("data/predicted.csv")
    return {"clusters": rows[:limit], "cluster_count": len(rows),
            "predicted": pred[:limit], "predicted_count": len(pred)}

@app.get("/blocklist")
def blocklist(limit: int = 50):
    items = list(BLOCKLIST.values())[-limit:]
    return {"total": len(BLOCKLIST), "showing": len(items), "items": items}

# ---------------------------------------------------------------- check
@app.post("/check")
def check(body: UrlIn):
    raw = body.url.strip()
    host = (urlparse(raw).hostname if "://" in raw else raw.split("/")[0]) or raw
    host = host.lower().strip(".")
    reg = host if host.endswith(FREE_HOSTS) else reg_of(host)

    hit = BLOCKLIST.get(reg) or BLOCKLIST.get(host)
    if hit:
        seen = str(hit.get("first_seen") or "")[:10]
        src = hit.get("source", "")
        note = "Already confirmed as a scam domain"
        if seen and src: note += f" (first seen {seen}, found by {src})"
        elif seen:       note += f" (first seen {seen})"
        return {"url": raw, "host": host, "reg_domain": reg,
                "verdict": "malicious", "score": 100, "cached": True,
                "reasons": [{"code": "known", "direction": "risk", "text": note}],
                "checked_at": now()}

    f = string_feats(host)
    rules = {k: v for k, v in f.items() if k.startswith("_rule")}
    row   = {k: v for k, v in f.items() if not k.startswith("_rule")}

    row.update(rdap_features(reg_of(host)))
    for c in FEATS:
        row.setdefault(c, 0)

    X = pd.DataFrame([row])[FEATS]
    score = float(MODEL.predict_proba(X)[0, 1])

    tls  = tls_facts(host) if body.deep else {}
    page = page_facts(raw) if body.deep else {}

    hard, soft = [], []

    if rules.get("_rule_brand_misplaced"):
        hard.append(RULE_TEXT["_rule_brand_misplaced"])
    for b in page.get("hotlinks_brand", []):
        hard.append(f"Loads images or stylesheets directly from {b}'s real website")

    sim, sim_brand = page.get("sim_overall", 0), page.get("sim_brand")
    if sim_brand and not page.get("sim_is_that_brand"):
        d = page.get("sim_detail", {})
        if sim >= SIM_HARD:
            hard.append(f"Page structure is {int(sim*100)}% identical to the real "
                        f"{sim_brand} website but hosted on a different domain")
        elif sim >= SIM_SOFT:
            soft.append(f"Shares {int(d.get('classes',0)*100)}% of CSS class names "
                        f"with the real {sim_brand} website")

    if page.get("card_outside_gateway"):
        hard.append("Card details are submitted to a domain that is not a known payment gateway")
    if page.get("form_cross_domain"):
        hard.append("A form on this page submits data to a different domain")
    if page.get("has_password") and row.get("age_bucket", -1) in (0, 1):
        hard.append("Password field on a domain registered within the last month")

    if tls.get("tls_free_ca") and row.get("age_bucket", -1) in (0, 1, 2):
        soft.append("Free certificate issued for a very new domain")
    if tls and not tls.get("tls_has_org") and row.get("brand_in_dom"):
        soft.append("Claims a known brand but the certificate carries no verified organisation")
    if page.get("redirect_count", 0) >= 2:
        soft.append(f"Redirects through {page['redirect_count']} hops before landing")
    for k in ("_rule_kw_in_sub", "_rule_deep_sub"):
        if rules.get(k):
            soft.append(RULE_TEXT[k])

    llm = {}
    if body.deep and not hard and ESCALATE <= score < BLOCK:
        llm = llm_check(evidence_packet(host, row, tls, page))
        if llm.get("impersonated_brand") and llm.get("confidence", 0) >= 70:
            hard.append(f"Page content impersonates {llm['impersonated_brand']} "
                        f"({str(llm.get('intent','')).replace('_',' ')})")
        for e in (llm.get("evidence") or [])[:2]:
            if isinstance(e, str):
                soft.append(e)

    reasons  = [{"code": "rule", "direction": "risk", "text": t} for t in hard]
    reasons += [{"code": "rule", "direction": "risk", "text": t} for t in soft]
    for name, _ in sorted(zip(FEATS, MODEL.feature_importances_), key=lambda kv: -kv[1]):
        if len(reasons) >= 6:
            break
        if row.get(name) and name in TEXT:
            reasons.append({"code": name, "direction": "risk", "text": TEXT[name]})

    if row.get("age_bucket", -1) >= 4 and not hard:
        reasons.append({"code": "age_bucket", "direction": "safe",
                        "text": "Domain has been registered for years"})
    if page.get("sim_is_that_brand"):
        reasons.insert(0, {"code": "official", "direction": "safe",
                           "text": f"This is {sim_brand}'s own website"})

    verdict = ("malicious" if hard or score >= BLOCK
               else "suspicious" if score >= ESCALATE or soft
               else "clean")
    if page.get("sim_is_that_brand") and not hard:
        verdict = "clean"

    final_score = min(100, round(score * 100) + 25 * len(hard))

    if verdict == "malicious":
        remember(reg, "user_submission", final_score)

    return {"url": raw, "host": host, "reg_domain": reg,
            "verdict": verdict, "score": final_score, "cached": False,
            "reasons": reasons[:6],
            "enrichment": {
                "age_bucket": row.get("age_bucket"),
                "rdap_found": row.get("rdap_found"),
                **{k: v for k, v in tls.items() if k != "tls_issuer"},
                **{k: v for k, v in page.items()
                   if k not in ("title", "sim_detail", "text")},
                "title": page.get("title", ""),
                "sim_detail": page.get("sim_detail", {}),
                "llm": llm,
            },
            "checked_at": now()}

@app.post("/check-number")
def check_number(body: NumIn):
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

    reasons, score = [], 0
    kind = phonenumbers.number_type(n)
    if kind == T.MOBILE:
        score += 70
        reasons.append({"code": "mobile_prefix", "direction": "risk",
                        "text": "Personal mobile number - UAE banks, couriers and "
                                "government bodies publish toll-free or landline numbers"})
    elif kind in (T.TOLL_FREE, T.FIXED_LINE):
        reasons.append({"code": "line_type", "direction": "safe",
                        "text": "Toll-free or landline, consistent with a real helpline"})
    elif kind == T.VOIP:
        score += 50
        reasons.append({"code": "voip", "direction": "risk",
                        "text": "VOIP line, unusual for an official helpline"})

    brand = (body.brand_context or "").lower()
    if brand and BRAND_NUMBERS.get(brand):
        score += 25
        reasons.append({"code": "not_in_official_set", "direction": "risk",
                        "text": f"Not among {body.brand_context}'s published numbers"})

    return {"number": e164,
            "verdict": "malicious" if score >= 85 else
                       "suspicious" if score >= 40 else "clean",
            "score": min(score, 100), "reasons": reasons, "checked_at": now()}