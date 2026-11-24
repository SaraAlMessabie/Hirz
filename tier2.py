"""
Request-time enrichment.
  rdap_features() -> the 4 fields the model was trained on
  tls_facts()     -> certificate rules (NOT model features)
  page_facts()    -> HTML rules, hotlinks, reference similarity, page text
"""
import json, pathlib, socket, ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx, tldextract
from bs4 import BeautifulSoup

try:
    from reference_pages import fingerprint, similarity
    HAVE_REFS = True
except Exception:
    HAVE_REFS = False

CACHE = pathlib.Path("cache/rdap"); CACHE.mkdir(parents=True, exist_ok=True)
UA = {"User-Agent": "Mozilla/5.0 (compatible; scam-detect-research/0.1)",
      "Accept": "application/rdap+json"}
BROWSER_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"}

FREE_CA = ("let's encrypt", "zerossl", "google trust", "buypass", "actalis")
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly",
              "bl.ink", "s.id", "tiny.cc", "lnkd.in", "t.ly")

BOT_UA = {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; "
                        "+http://www.google.com/bot.html)"}

GATEWAYS = ("network.ae", "telr.com", "paytabs.com", "payfort.com",
            "amazonpaymentservices.com", "checkout.com", "magnati.com",
            "stripe.com", "adyen.com", "ngenius-payments.com")


def reg_of(host):
    e = tldextract.extract(host or "")
    return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else (host or "")


_REFS, _REF_DOMAINS = None, None


def references():
    global _REFS, _REF_DOMAINS
    if _REFS is None:
        p = pathlib.Path("data/references.json")
        _REFS = json.loads(p.read_text("utf-8")) if (HAVE_REFS and p.exists()) else {}
        _REF_DOMAINS = {}
        for brand, fps in _REFS.items():
            doms = set()
            for fp in fps:
                h = urlparse(fp.get("url", "")).hostname or ""
                if h:
                    doms.add(reg_of(h))
            _REF_DOMAINS[brand] = doms
    return _REFS, _REF_DOMAINS


_BOOT = None


def bootstrap():
    global _BOOT
    if _BOOT is None:
        _BOOT = {}
        try:
            data = httpx.get("https://data.iana.org/rdap/dns.json",
                             timeout=20, headers=UA).json()
            for tlds, urls in data["services"]:
                for t in tlds:
                    _BOOT[t.lower()] = urls[0].rstrip("/")
        except Exception:
            pass
    return _BOOT


def _days(iso):
    try:
        return (datetime.now(timezone.utc)
                - datetime.fromisoformat(iso.replace("Z", "+00:00"))).days
    except Exception:
        return None


def age_bucket(days):
    if days is None or days < 0:
        return -1
    for i, lim in enumerate([7, 30, 90, 365, 1095]):
        if days < lim:
            return i
    return 5


def rdap_features(domain):
    out = {"rdap_found": 0, "age_bucket": -1, "expiry_short": 0, "ns_count": 0}
    if not domain:
        return out
    f = CACHE / f"{domain}.json"
    d = None
    if f.exists():
        try:
            d = json.loads(f.read_text("utf-8"))
        except Exception:
            d = None
    if d is None:
        base = bootstrap().get(domain.rsplit(".", 1)[-1])
        if not base:
            return out
        try:
            r = httpx.get(f"{base}/domain/{domain}", timeout=8,
                          headers=UA, follow_redirects=True)
            d = r.json() if r.status_code == 200 else {"_notfound": r.status_code}
            if r.status_code in (200, 404):
                f.write_text(json.dumps(d), "utf-8")
        except Exception:
            return out
    if not isinstance(d, dict) or "events" not in d:
        return out

    created = expires = None
    for ev in d.get("events") or []:
        a = (ev.get("eventAction") or "").lower()
        if a == "registration":
            created = ev.get("eventDate")
        if a == "expiration":
            expires = ev.get("eventDate")

    exp_days = -(_days(expires)) if expires else -1
    out.update(rdap_found=1,
               age_bucket=age_bucket(_days(created) if created else None),
               expiry_short=int(0 <= exp_days <= 365),
               ns_count=min(len(d.get("nameservers") or []), 10))
    return out


def tls_facts(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                c = ss.getpeercert()
    except Exception:
        return {}
    issuer = " ".join(v for t in c.get("issuer", ()) for _, v in t).lower()
    org = [v for t in c.get("subject", ()) for k, v in t if k == "organizationName"]
    try:
        days = (datetime.now(timezone.utc)
                - datetime.strptime(c.get("notBefore"), "%b %d %H:%M:%S %Y %Z")
                  .replace(tzinfo=timezone.utc)).days
    except Exception:
        days = -1
    sans = [v for k, v in c.get("subjectAltName", ()) if k == "DNS"]
    return {"tls_issuer": issuer[:80],
            "tls_free_ca": int(any(ca in issuer for ca in FREE_CA)),
            "tls_has_org": int(bool(org)), "tls_org": org[0] if org else "",
            "tls_age_days": days, "tls_san_count": len(sans)}


def page_facts(url):
    if "://" not in url:
        url = "https://" + url
    try:
        r = httpx.get(url, timeout=10, follow_redirects=True, headers=BROWSER_UA)
    except Exception:
        return {}

    final = str(r.url)
    page_reg = reg_of(urlparse(final).hostname or "")

    # which hosts did we pass through, and was a shortener among them?
    chain = [str(h.url) for h in r.history] + [final]
    chain_hosts = [reg_of(urlparse(u).hostname or "") for u in chain]
    out = {"redirect_count": len(r.history), "final_url": final,
           "status": r.status_code,
           "redirect_chain": chain[:6],
           "via_shortener": int(any(h in SHORTENERS for h in chain_hosts)),
           "landed_elsewhere": int(bool(r.history) and chain_hosts[0] != page_reg)}

    # cloaking: does the site answer a crawler differently from a browser?
    try:
        rb = httpx.get(url, timeout=8, follow_redirects=True, headers=BOT_UA)
        same_len = abs(len(rb.text) - len(r.text)) <= max(200, len(r.text) * 0.15)
        out["cloaked"] = int(not same_len or rb.status_code != r.status_code)
        out["cloak_detail"] = (f"browser {r.status_code}/{len(r.text)}b vs "
                               f"crawler {rb.status_code}/{len(rb.text)}b")
    except Exception:
        out["cloaked"] = 0

    try:
        soup = BeautifulSoup(r.text, "lxml")
    except Exception:
        return out

    cross = pw = card = gw_ok = 0
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if action.startswith("http"):
            a_reg = reg_of(urlparse(action).hostname or "")
            if a_reg and a_reg != page_reg:
                cross = 1
                if any(g in action.lower() for g in GATEWAYS):
                    gw_ok = 1
        for inp in form.find_all("input"):
            t = (inp.get("type") or "").lower()
            n = ((inp.get("name") or "") + (inp.get("id") or "")).lower()
            if t == "password":
                pw = 1
            if any(k in n for k in ("card", "cvv", "cvc", "creditcard", "pan")):
                card = 1

    hotlinked = set()
    for t in soup.find_all(["img", "script", "link"]):
        src = (t.get("src") or t.get("href") or "")
        if src.startswith("http"):
            hr = reg_of(urlparse(src).hostname or "")
            if hr and hr != page_reg:
                hotlinked.add(hr)

    out.update({
        "form_cross_domain": cross,
        "has_password": pw,
        "has_card_field": card,
        "card_outside_gateway": int(card and cross and not gw_ok),
        "has_favicon": int(bool(soup.find("link",
                           rel=lambda v: v and "icon" in v.lower()))),
        "title": (soup.title.string or "")[:120] if soup.title else "",
        "text": soup.get_text(" ", strip=True)[:2000],
        "hotlinked_domains": sorted(hotlinked),
        "page_reg": page_reg,
    })

    refs, ref_domains = references()
    if refs:
        try:
            sus = fingerprint(r.text, final)
        except Exception:
            return out
        best_brand, best_score, best_detail = None, 0.0, {}
        for brand, fps in refs.items():
            for fp in fps:
                s = similarity(sus, fp)
                if s["overall"] > best_score:
                    best_brand, best_score, best_detail = brand, s["overall"], s
        if best_brand:
            out.update({
                "sim_brand": best_brand,
                "sim_overall": best_score,
                "sim_detail": {k: round(v, 3) for k, v in best_detail.items()},
                "sim_is_that_brand": int(page_reg in ref_domains.get(best_brand, set())),
                "hotlinks_brand": sorted(
                    {b for b, doms in ref_domains.items()
                     if doms & set(out["hotlinked_domains"])}),
            })
    return out
