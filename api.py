"""
Scam detection API.
  POST /check          {"url": "...", "deep": true}
  POST /check-number   {"number": "+971...", "brand_context": "ADCB"}
  GET  /stats  /detections  /campaigns  /blocklist
"""
import csv, json, pathlib, re, time, uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import joblib, pandas as pd, phonenumbers
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from phonenumbers import PhoneNumberType as T

from features import string_feats, reg_of, FREE_HOSTS
from tier2 import rdap_features, tls_facts, page_facts
from llm_check import evidence_packet, llm_check

try:
    import evidence as evidence_mod          # teammate's bilingual PDF builder
    HAVE_EVIDENCE = True
except Exception:
    HAVE_EVIDENCE = False

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


CLIENTS = pathlib.Path("clients")
if CLIENTS.is_dir():
    app.mount("/app", StaticFiles(directory="clients", html=True), name="clients")


@app.get("/dashboard")
def dashboard():
    """The investigator console."""
    f = CLIENTS / "dashboard.html"
    if f.exists():
        return FileResponse(f)
    return {"error": "clients/dashboard.html not found - are you on the full-system branch?"}


@app.get("/api")
def root():
    return {"service": "scam-detect", "status": "ok",
            "endpoints": ["POST /check", "POST /check-number", "GET /stats",
                          "GET /detections", "GET /campaigns", "GET /confirmed",
                          "GET/POST /official", "POST /evidence",
                          "POST /report", "GET /reports",
                          "POST /scan-message",
                          "POST /review", "GET /reviews"],
            "docs": "/docs", "features": len(FEATS),
            "confirmed": len(CONFIRMED), "reported": len(REPORTED),
            "official": len(OFFICIAL_DOMAINS), "cached": len(CHECK_CACHE),
            "official_numbers": len(OFFICIAL),
            "thresholds": {"escalate": ESCALATE, "block": BLOCK}}


@app.get("/")
def home():
    """Send a browser to the console, not to JSON."""
    if (CLIENTS / "dashboard.html").exists():
        return RedirectResponse("/dashboard")
    return RedirectResponse("/docs")


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


@app.post("/evidence")
def evidence_report(body: UrlIn):
    """Timestamped, hashed evidence bundle + bilingual PDF for a URL.
    Re-runs the check itself rather than trusting anything sent in."""
    if not HAVE_EVIDENCE:
        raise HTTPException(503, "evidence module not available")
    result = check(UrlIn(url=body.url, deep=True))
    bundle = evidence_mod.build(result)
    _, pdf_path = evidence_mod.save(bundle)
    data = pathlib.Path(pdf_path).read_bytes()
    eid = bundle["evidence_id"]
    return Response(data, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="hirz-evidence-{eid}.pdf"',
        "X-Evidence-Id": eid,
        "X-Bundle-SHA256": bundle.get("bundle_sha256", ""),
    })


@app.get("/evidence/{evidence_id}")
def evidence_fetch(evidence_id: str):
    """Re-download a bundle already on disk."""
    safe = "".join(c for c in evidence_id if c.isalnum() or c in "-_")
    p = pathlib.Path("evidence") / f"{safe}.pdf"
    if not p.exists():
        raise HTTPException(404, "no such evidence report")
    return FileResponse(p, media_type="application/pdf",
                        filename=f"hirz-evidence-{safe}.pdf")


# ------------------------------------------------- citizen reporting
REPORTS_FILE = pathlib.Path("data/reports.csv")
REPORT_FIELDS = ["report_id", "type", "description", "url", "phone", "email",
                 "reporter", "status", "created_at", "auto_verdict", "auto_score"]


class ReportIn(BaseModel):
    type: str = "other"          # phone | email | sms | website | other
    description: str = ""
    url: str | None = None
    phone: str | None = None
    email: str | None = None
    reporter: str = "anonymous"


@app.post("/report")
def submit_report(body: ReportIn):
    """A citizen reports a scam. Goes to the investigator queue as pending.
    If a URL or number was given we run our own check and attach the verdict,
    so the reviewer opens the case with evidence already on it."""
    if not any([body.url, body.phone, body.email, body.description.strip()]):
        raise HTTPException(400, "give at least a URL, a number, an email or a description")

    auto_verdict, auto_score = "", ""
    try:
        if body.url:
            v = check(UrlIn(url=body.url, deep=True))
            auto_verdict, auto_score = v.get("status", ""), v.get("score", "")
        elif body.phone:
            v = check_number(NumIn(number=body.phone))
            auto_verdict, auto_score = v.get("verdict", ""), v.get("score", "")
    except Exception:
        pass

    rid = "R-" + uuid.uuid4().hex[:8].upper()
    row = {"report_id": rid, "type": body.type,
           "description": body.description[:2000],
           "url": body.url or "", "phone": body.phone or "",
           "email": body.email or "", "reporter": body.reporter,
           "status": "pending", "created_at": now(),
           "auto_verdict": auto_verdict, "auto_score": auto_score}

    fresh = not REPORTS_FILE.exists()
    with REPORTS_FILE.open("a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=REPORT_FIELDS)
        if fresh:
            w.writeheader()
        w.writerow(row)

    return {"ok": True, "report_id": rid, "status": "pending",
            "auto_verdict": auto_verdict, "auto_score": auto_score,
            "message": "Report received. An investigator will review it.",
            "created_at": row["created_at"]}


@app.get("/reports")
def list_reports(status: str = None, reporter: str = None, limit: int = 100):
    """The investigator queue, or one citizen's own reports."""
    rows = _rows("data/reports.csv")
    if status:
        rows = [r for r in rows if r.get("status") == status]
    if reporter:
        rows = [r for r in rows if r.get("reporter") == reporter]
    rows.reverse()
    counts = {}
    for r in _rows("data/reports.csv"):
        counts[r.get("status", "?")] = counts.get(r.get("status", "?"), 0) + 1
    return {"total": len(rows), "counts": counts, "items": rows[:limit]}


class ReportStatusIn(BaseModel):
    report_id: str
    status: str                   # under_review | confirmed | rejected
    reviewer: str = "investigator"
    note: str = ""


@app.post("/report-status")
def set_report_status(body: ReportStatusIn):
    """Investigator moves a report through the queue. Confirming a report
    also confirms the identifiers on it."""
    allowed = ("pending", "under_review", "confirmed", "rejected")
    if body.status not in allowed:
        raise HTTPException(400, f"status must be one of {allowed}")

    rows = _rows("data/reports.csv")
    found = False
    for r in rows:
        if r.get("report_id") == body.report_id:
            r["status"] = body.status
            found = True
    if not found:
        raise HTTPException(404, "no such report")

    with REPORTS_FILE.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=REPORT_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in REPORT_FIELDS})

    promoted = []
    if body.status == "confirmed":
        for r in rows:
            if r.get("report_id") != body.report_id:
                continue
            if r.get("url"):
                host = (urlparse(r["url"]).hostname if "://" in r["url"]
                        else r["url"].split("/")[0]) or r["url"]
                d = reg_of(host.lower().strip("."))
                record_review(d, "confirm", body.reviewer,
                              f"via report {body.report_id}")
                promoted.append(d)
        CHECK_CACHE.clear()

    return {"ok": True, "report_id": body.report_id, "status": body.status,
            "promoted_to_confirmed": promoted}


# ------------------------------------------------- message scanning
URL_RE   = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']{4,}", re.I)
PHONE_RE = re.compile(
    r"(?:\+971|00971|0)[\s-]?5\d[\s-]?\d{3}[\s-]?\d{4}"      # mobile
    r"|(?:\+971|00971|0)[\s-]?[2-4679][\s-]?\d{3}[\s-]?\d{4}"  # landline
    r"|\b[68]00[\s-]?\d{2,4}(?:[\s-]?\d{2,4})?\b")             # 600/800
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")

URGENCY = {"urgent", "immediately", "suspended", "verify", "expire", "expired",
           "final notice", "within 24 hours", "act now", "blocked", "penalty",
           "customs", "clearance", "unpaid", "reactivate", "confirm now"}
ARABIC_URGENCY = {"عاجل", "تحقق", "تعليق", "الحساب", "تأكيد", "الجمارك", "رسوم"}


class MessageIn(BaseModel):
    text: str
    lang: str | None = None


@app.post("/scan-message")
def scan_message(body: MessageIn):
    """Paste an SMS or email. Pulls out the links, numbers and addresses,
    checks each one, and reports the language and pressure tactics."""
    text = (body.text or "").strip()
    if not text:
        raise HTTPException(400, "no text given")

    urls   = list(dict.fromkeys(URL_RE.findall(text)))[:5]
    phones = list(dict.fromkeys(m.strip() for m in PHONE_RE.findall(text)))[:5]
    emails = list(dict.fromkeys(EMAIL_RE.findall(text)))[:5]

    low = text.lower()
    hits = sorted({k for k in URGENCY if k in low} |
                  {k for k in ARABIC_URGENCY if k in text})
    has_arabic = any("\u0600" <= c <= "\u06ff" for c in text)

    url_results, worst, worst_status = [], 0, "NO_MATCH"
    for u in urls:
        try:
            v = check(UrlIn(url=u if "://" in u else "https://" + u, deep=True))
        except Exception:
            continue
        url_results.append({"url": u, "status": v.get("status"),
                            "score": v.get("score"),
                            "reasons": [x["text"] for x in (v.get("reasons") or [])[:3]]})
        if (v.get("score") or 0) > worst:
            worst, worst_status = v["score"], v.get("status", worst_status)

    phone_results = []
    for p in phones:
        try:
            v = check_number(NumIn(number=p))
        except Exception:
            continue
        phone_results.append({"number": p, "verdict": v.get("verdict"),
                              "score": v.get("score"),
                              "reasons": [x["text"] for x in (v.get("reasons") or [])[:2]]})
        if (v.get("score") or 0) > worst:
            worst = v["score"]

    indicators = []
    if hits:
        indicators.append({"type": "urgency",
                           "description": "Pressure language: " + ", ".join(hits[:5])})
    if urls and not url_results:
        indicators.append({"type": "unreachable",
                           "description": "The links in this message could not be reached"})
    for r in url_results:
        if r["status"] in ("CONFIRMED", "REPORTED"):
            indicators.append({"type": "known_bad",
                               "description": f"{r['url']} is already flagged"})
    for r in phone_results:
        if r["verdict"] in ("malicious", "suspicious"):
            indicators.append({"type": "suspicious_number",
                               "description": f"{r['number']}: " +
                                              (r["reasons"][0] if r["reasons"] else "unusual for a helpline")})

    if worst >= 80 or worst_status == "CONFIRMED":
        risk = "high"
    elif worst >= 30 or len(hits) >= 2:
        risk = "medium"
    elif urls or phones:
        risk = "low"
    else:
        risk = "unknown"

    recs = ["Do not click the links in this message.",
            "Contact the organisation using a number from their official website, "
            "not one in the message."]
    if phone_results:
        recs.append("Do not call back the number in this message.")
    if risk == "unknown":
        recs = ["We found nothing to check in this message. "
                "That does not mean it is safe."]

    return {"risk_level": risk,
            "language": "ar" if has_arabic else "en",
            "summary": (f"{len(urls)} link(s), {len(phones)} number(s), "
                        f"{len(emails)} address(es) found"),
            "indicators": indicators,
            "urls": url_results, "phone_numbers": phone_results,
            "email_addresses": emails,
            "recommendations": recs,
            "advisory": ADVISORY, "checked_at": now()}


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
