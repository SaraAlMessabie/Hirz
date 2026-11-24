"""
Scam detection API.
  POST /check          {"url": "...", "deep": true}
  POST /check-number   {"number": "+971...", "brand_context": "ADCB"}
  GET  /stats  /detections  /campaigns  /blocklist
"""
import csv, json, pathlib, time
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
    "_rule_mixed_script":     "Domain mixes alphabets in a single label - a look-alike technique",
}


ADVISORY = ("Automated risk assessments are advisory and are not proof of fraud.")

NO_MATCH_TEXT = ("No known reports found for this address. "
                 "This does not guarantee it is safe.")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _rows(path):
    p = pathlib.Path(path)
    if not p.exists():
        return []
    return list(csv.DictReader(p.read_text("utf-8", errors="ignore").splitlines()))


# ------------------------------------------------- confirmed / reported
# CONFIRMED  = a human verified it. The ONLY thing we serve as certain.
# REPORTED   = discovery or a user flagged it. Unverified.
CONFIRMED_FILE = pathlib.Path("data/confirmed.csv")
REVIEWS_FILE   = pathlib.Path("data/reviews.csv")

CONFIRMED, REPORTED = {}, {}


def load_lists():
    CONFIRMED.clear(); REPORTED.clear()
    for row in _rows("data/confirmed.csv"):
        if row.get("domain"):
            CONFIRMED[row["domain"]] = row
    for path, src_name in (("data/ct_hits.csv", "certificate_transparency"),
                           ("data/lookalikes_triaged.csv", "permutation_sweep"),
                           ("data/blocklist.csv", "user_submission")):
        for row in _rows(path):
            d = (row.get("domain") or "").strip()
            if not d or d in CONFIRMED or d in REPORTED:
                continue
            if " " in d or "." not in d or "," in d:      # not a domain
                continue
            try:
                sc = float(row.get("score") or 0)
            except ValueError:
                sc = 0
            REPORTED[d] = {"domain": d, "source": row.get("source") or src_name,
                           "score": sc,
                           "first_seen": row.get("first_seen_by_us")
                                         or row.get("first_seen") or ""}
    print(f"confirmed: {len(CONFIRMED)}  |  reported (unverified): {len(REPORTED)}")


def remember_reported(domain, source, score):
    if not domain or domain in CONFIRMED or domain in REPORTED:
        return
    rec = {"domain": domain, "source": source, "score": score, "first_seen": now()}
    REPORTED[domain] = rec
    p = pathlib.Path("data/blocklist.csv")
    fresh = not p.exists()
    with p.open("a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if fresh:
            w.writerow(["domain", "source", "score", "first_seen"])
        w.writerow([domain, source, score, rec["first_seen"]])


def record_review(domain, decision, reviewer, note=""):
    """Audit trail. Confirm is the ONLY path into CONFIRMED."""
    fresh = not REVIEWS_FILE.exists()
    with REVIEWS_FILE.open("a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if fresh:
            w.writerow(["domain", "decision", "reviewer", "note", "reviewed_at"])
        w.writerow([domain, decision, reviewer, note, now()])

    if decision == "confirm":
        rec = REPORTED.pop(domain, {"domain": domain, "source": "manual", "score": ""})
        rec["confirmed_by"] = reviewer
        rec["confirmed_at"] = now()
        CONFIRMED[domain] = rec
        fresh = not CONFIRMED_FILE.exists()
        with CONFIRMED_FILE.open("a", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            if fresh:
                w.writerow(["domain", "source", "score", "first_seen",
                            "confirmed_by", "confirmed_at"])
            w.writerow([domain, rec.get("source", ""), rec.get("score", ""),
                        rec.get("first_seen", ""), reviewer, rec["confirmed_at"]])
    elif decision == "reject":
        REPORTED.pop(domain, None)
        CONFIRMED.pop(domain, None)


load_lists()

# ------------------------------------------------- official / verified
# Checked BEFORE anything else. A real bank or government site must never
# reach the heuristics - Criterion 1 penalises exactly that false positive.
OFFICIAL_FILE = pathlib.Path("data/official.csv")
OFFICIAL_DOMAINS = {}

# Restricted second-level domains: only the named authority can register under
# them, so an anchored suffix match is safe. Note this matches the FULL host,
# so "tamm.abudhabi.gov.ae.evil.xyz" does NOT match.
OFFICIAL_SUFFIXES = (".gov.ae", ".mil.ae", ".ac.ae", ".sch.ae",
                     ".gov.uk", ".gov", ".mil")


def load_official():
    OFFICIAL_DOMAINS.clear()
    for row in _rows("data/official.csv"):
        d = (row.get("domain") or "").strip().lower()
        if d:
            OFFICIAL_DOMAINS[d] = row
    print(f"official allowlist: {len(OFFICIAL_DOMAINS)} domains "
          f"+ {len(OFFICIAL_SUFFIXES)} restricted suffixes")


def official_hit(host, reg):
    """Exact registrable-domain match, or a restricted government suffix."""
    rec = OFFICIAL_DOMAINS.get(reg) or OFFICIAL_DOMAINS.get(host)
    if rec:
        return rec, f"Listed as an official domain of {rec.get('org') or reg}"
    for suf in OFFICIAL_SUFFIXES:
        if host.endswith(suf):
            return ({"domain": reg, "org": "government entity",
                     "source": "restricted_suffix"},
                    f"Registered under {suf}, which only government "
                    f"entities may use")
    return None, ""


def add_official(domain, org, source, added_by):
    d = domain.strip().lower()
    if d in OFFICIAL_DOMAINS:
        return False
    rec = {"domain": d, "org": org, "source": source,
           "added_by": added_by, "added_at": now()}
    OFFICIAL_DOMAINS[d] = rec
    fresh = not OFFICIAL_FILE.exists()
    with OFFICIAL_FILE.open("a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if fresh:
            w.writerow(["domain", "org", "source", "added_by", "added_at"])
        w.writerow([d, org, source, added_by, rec["added_at"]])
    return True


load_official()

# ------------------------------------------------- deep-result cache
# Avoids re-running a 10s analysis on a domain we just checked.
# TTL is age-dependent: a domain registered last week can be weaponised
# tomorrow, a twenty-year-old one cannot.
CACHE_FILE = pathlib.Path("data/check_cache.json")
CHECK_CACHE = {}

TTL_BY_AGE = {-1: 1800, 0: 900, 1: 1800, 2: 7200,
              3: 86400, 4: 604800, 5: 604800}


def load_cache():
    if CACHE_FILE.exists():
        try:
            CHECK_CACHE.update(json.loads(CACHE_FILE.read_text("utf-8")))
        except Exception:
            pass
    print(f"deep-check cache: {len(CHECK_CACHE)} entries")


def cache_get(key):
    e = CHECK_CACHE.get(key)
    if not e:
        return None
    age_b = (e.get("result", {}).get("enrichment") or {}).get("age_bucket", -1)
    ttl = TTL_BY_AGE.get(age_b if isinstance(age_b, int) else -1, 1800)
    if time.time() - e.get("at", 0) > ttl:
        CHECK_CACHE.pop(key, None)
        return None
    return e["result"]


def cache_put(key, result):
    CHECK_CACHE[key] = {"at": time.time(), "result": result}
    try:
        CACHE_FILE.write_text(json.dumps(CHECK_CACHE)[:8_000_000], "utf-8")
    except Exception:
        pass


load_cache()

# ---------------------------------------------------------------- helplines
OFFICIAL, BRAND_NUMBERS = set(), {}
for _row in _rows("data/helplines.csv"):
    _num = (_row.get("number") or "").strip()
    if _num:
        OFFICIAL.add(_num)
        BRAND_NUMBERS.setdefault((_row.get("brand") or "").lower(), set()).add(_num)
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
            "endpoints": ["POST /check", "POST /check-number", "GET /stats",
                          "GET /detections", "GET /campaigns", "GET /confirmed",
                          "GET/POST /official",
                          "POST /review", "GET /reviews"],
            "docs": "/docs", "features": len(FEATS),
            "confirmed": len(CONFIRMED), "reported": len(REPORTED),
            "official": len(OFFICIAL_DOMAINS), "cached": len(CHECK_CACHE),
            "official_numbers": len(OFFICIAL),
            "thresholds": {"escalate": ESCALATE, "block": BLOCK}}


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
              if str(r.get("age_bucket", "")).strip().split(".")[0] in ("0", "1", "2", "3")]
    mx = sum(1 for r in recent if str(r.get("has_mx")).startswith("1"))
    return {"ct_discoveries": len(ct),
            "unknown_to_public_feeds": unknown,
            "permutation_total": len(lk),
            "permutation_recent": len(recent),
            "permutation_with_mx": mx,
            "confirmed": len(CONFIRMED), "reported": len(REPORTED),
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
    seen, uniq = set(), []
    for r in out:
        if r["domain"] in seen:
            continue
        seen.add(r["domain"]); uniq.append(r)
    uniq.sort(key=lambda x: x["score"], reverse=True)
    return {"total": len(uniq), "showing": min(limit, len(uniq)),
            "items": uniq[:limit]}


@app.get("/campaigns")
def campaigns(limit: int = 50):
    rows = _rows("data/campaigns.csv")
    pred = _rows("data/predicted.csv")
    return {"clusters": rows[:limit], "cluster_count": len(rows),
            "predicted": pred[:limit], "predicted_count": len(pred)}


@app.get("/confirmed")
def confirmed_list(limit: int = 50):
    items = list(CONFIRMED.values())[-limit:]
    return {"total": len(CONFIRMED), "showing": len(items), "items": items}


class ReviewIn(BaseModel):
    domain: str
    decision: str          # "confirm" | "reject"
    reviewer: str = "investigator"
    note: str = ""


@app.post("/review")
def review(body: ReviewIn):
    """The only path from REPORTED into CONFIRMED. Human in the loop."""
    d = body.domain.strip().lower()
    if body.decision not in ("confirm", "reject"):
        return {"ok": False, "error": "decision must be confirm or reject"}
    record_review(d, body.decision, body.reviewer, body.note)
    CHECK_CACHE.clear()
    return {"ok": True, "domain": d, "decision": body.decision,
            "confirmed": len(CONFIRMED), "reported": len(REPORTED),
            "reviewed_at": now()}


class OfficialIn(BaseModel):
    domain: str
    org: str = ""
    source: str = ""
    added_by: str = "investigator"


@app.get("/official")
def official(limit: int = 200):
    return {"total": len(OFFICIAL_DOMAINS),
            "restricted_suffixes": list(OFFICIAL_SUFFIXES),
            "items": list(OFFICIAL_DOMAINS.values())[:limit]}


@app.post("/official")
def official_add(body: OfficialIn):
    """Add a verified official domain. Sourced from the organisation's own site."""
    ok = add_official(body.domain, body.org, body.source, body.added_by)
    CHECK_CACHE.clear()                 # a new allowlist entry invalidates cache
    return {"ok": ok, "domain": body.domain.strip().lower(),
            "total": len(OFFICIAL_DOMAINS),
            "note": "already listed" if not ok else "added"}


@app.get("/reviews")
def reviews(limit: int = 100):
    rows = _rows("data/reviews.csv")
    return {"total": len(rows), "items": rows[-limit:]}


@app.post("/check")
def check(body: UrlIn):
    raw = body.url.strip()
    host = (urlparse(raw).hostname if "://" in raw else raw.split("/")[0]) or raw
    host = host.lower().strip(".")
    reg = host if host.endswith(FREE_HOSTS) else reg_of(host)

    # 0a. official / verified - before every heuristic
    off, off_text = official_hit(host, reg)
    if off:
        return {"url": raw, "host": host, "reg_domain": reg,
                "status": "OFFICIAL", "verdict": "clean", "score": 0,
                "cached": True, "advisory": ADVISORY,
                "reasons": [{"code": "official", "direction": "safe",
                             "text": off_text}],
                "enrichment": {}, "checked_at": now()}

    # 0b. confirmed by a human
    conf = CONFIRMED.get(reg) or CONFIRMED.get(host)
    if conf:
        seen = str(conf.get("first_seen") or "")[:10]
        by = conf.get("confirmed_by", "")
        note = "Confirmed as a scam by a reviewer"
        if by:   note += f" ({by}"
        if by and seen: note += f", first seen {seen})"
        elif by: note += ")"
        elif seen: note += f" (first seen {seen})"
        return {"url": raw, "host": host, "reg_domain": reg,
                "status": "CONFIRMED", "verdict": "malicious", "score": 100,
                "cached": True, "advisory": ADVISORY,
                "reasons": [{"code": "confirmed", "direction": "risk", "text": note}],
                "enrichment": {}, "checked_at": now()}

    # 0c. did we already deep-check this recently?
    cache_key = f"{reg}|{int(body.deep)}"
    hitc = cache_get(cache_key)
    if hitc:
        out = dict(hitc)
        out["cached"] = True
        out["checked_at"] = hitc.get("checked_at")
        return out

    rep = REPORTED.get(reg) or REPORTED.get(host)
    if rep and not body.deep:
        return {"url": raw, "host": host, "reg_domain": reg,
                "status": "REPORTED", "verdict": "suspicious",
                "score": int(float(rep.get("score") or 50)), "cached": True,
                "advisory": ADVISORY,
                "reasons": [{"code": "reported", "direction": "risk",
                             "text": "Flagged by our discovery layer but not yet "
                                     "verified by a reviewer "
                                     f"(source: {rep.get('source','')})"}],
                "enrichment": {}, "checked_at": now()}

    f = string_feats(host)
    rules = {k: v for k, v in f.items() if k.startswith("_rule")}
    row = {k: v for k, v in f.items() if not k.startswith("_rule")}

    row.update(rdap_features(reg_of(host)))
    for c in FEATS:
        row.setdefault(c, 0)

    X = pd.DataFrame([row])[FEATS]
    score = float(MODEL.predict_proba(X)[0, 1])

    tls = tls_facts(host) if body.deep else {}
    page = page_facts(raw) if body.deep else {}

    hard, soft, clear = [], [], []

    # Extended Validation certificates require verified legal identity.
    # Scam domains do not have them - this is a conclusive clear.
    issuer = (tls.get("tls_issuer") or "").lower()
    if tls.get("tls_has_org") and (" ev " in f" {issuer} " or "extended validation" in issuer):
        clear.append(f"Extended Validation certificate issued to "
                     f"{tls.get('tls_org')} - requires verified legal identity")
    elif tls.get("tls_has_org") and row.get("age_bucket", -1) >= 4:
        clear.append(f"Certificate carries a verified organisation "
                     f"({tls.get('tls_org')}) on a domain registered years ago")

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

    if rules.get("_rule_mixed_script"):
        hard.append(RULE_TEXT["_rule_mixed_script"])
    if page.get("cloaked"):
        hard.append("Serves different content to a crawler than to a browser "
                    f"({page.get('cloak_detail','')}) - deliberate cloaking")
    if page.get("via_shortener"):
        soft.append("Reached through a URL shortener, which hides the destination")
    if page.get("landed_elsewhere"):
        soft.append(f"Redirected to a different domain: {page.get('page_reg','')}")

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

    reasons = [{"code": "verified", "direction": "safe", "text": t} for t in clear]
    reasons += [{"code": "rule", "direction": "risk", "text": t} for t in hard]
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

    if clear:
        hard = []                       # verified identity beats heuristics

    verdict = ("malicious" if hard or score >= BLOCK
               else "suspicious" if score >= ESCALATE or soft
               else "clean")
    if (page.get("sim_is_that_brand") or clear) and not hard:
        verdict = "clean"

    if rep:
        status = "REPORTED"
    elif verdict == "malicious":
        status = "REPORTED"             # never CONFIRMED without a human
    elif verdict == "suspicious":
        status = "SUSPICIOUS"
    elif not body.deep and not page:
        status = "UNKNOWN"
    else:
        status = "NO_MATCH"

    final_score = 0 if clear else min(100, round(score * 100) + 25 * len(hard))

    if verdict == "malicious":
        remember_reported(reg, "user_submission", final_score)

    if status == "NO_MATCH" and not reasons:
        reasons = [{"code": "no_match", "direction": "neutral", "text": NO_MATCH_TEXT}]

    result = {"url": raw, "host": host, "reg_domain": reg,
            "status": status, "verdict": verdict, "score": final_score,
            "cached": False, "advisory": ADVISORY,
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

    cache_put(cache_key, result)
    return result


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
