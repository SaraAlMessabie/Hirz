"""
Maps listings + NAP consistency (Task 3).

A fake "customer service" listing exists only on Google, because that is where
the scammer created it. Real branches also appear on the brand's own branch
list, on OpenStreetMap and across the web. We cross-reference and count
disagreements.

  python listing_scan.py                  reads data/fixtures/listings.json
  python listing_scan.py --api http://127.0.0.1:8000

Writes data/listing_hits.csv (one row per listing).

Signals (True = agrees with a real listing, False = disagrees, blank = not checked):
  phone_in_official     /check-number says the phone is the brand's published helpline
  address_in_branches   address matches a row in data/branches.csv for that brand
  found_in_osm          OpenStreetMap has this brand at this address (Nominatim, 1 req/s)
  web_mentions          web results for exact name + phone (needs BRAVE_API_KEY)
  website_official      listing's website is one of the brand's official domains

Env (all optional):
  GOOGLE_PLACES_KEY   fetch listings live from Google Places instead of the fixture
  BRAVE_API_KEY       enables the web-footprint signal
  NOMINATIM_EMAIL     contact address sent to Nominatim, per its usage policy
"""
import argparse, csv, hashlib, json, pathlib, re, sys, time
from urllib.parse import urlparse

import httpx

from tier2 import reg_of

DATA = pathlib.Path("data")
FIXTURE = DATA / "fixtures" / "listings.json"
OUT = DATA / "listing_hits.csv"
OSM_CACHE = pathlib.Path("cache/osm")
UA = "Hirz-hackathon-prototype/0.1 (scam listing research)"

DEFAULT_QUERIES = ["ADCB customer service", "Emirates NBD customer service Dubai",
                   "Aramex office Dubai", "Emirates Post office Abu Dhabi"]

# Words that appear in almost every UAE address and say nothing about *which* place.
STOP = {"dubai", "abu", "dhabi", "sharjah", "ajman", "fujairah", "ras", "al", "khaimah",
        "umm", "quwain", "uae", "united", "arab", "emirates", "st", "street", "rd", "road",
        "floor", "ground", "level", "building", "bldg", "shop", "office", "near", "next",
        "to", "the", "of", "and", "opp", "opposite", "beside", "behind", "po", "box",
        "zone", "city", "area", "first", "1st", "2nd", "unit", "no", "limit", "up", "kg"}


def toks(s):
    return {t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if len(t) > 1 and t not in STOP}


# ---------------------------------------------------------------- reference data
def load_refs():
    brands = {r["brand"]: r for r in csv.DictReader(open(DATA / "brands.csv", encoding="utf-8"))}
    branches = {}
    for r in csv.DictReader(open(DATA / "branches.csv", encoding="utf-8")):
        branches.setdefault(r["brand"], []).append(r)
    return brands, branches


def load_listings(places_key=""):
    if places_key:
        rows = []
        for q in DEFAULT_QUERIES:
            rows += places_search(q, places_key)
        if rows:
            return rows, "google_places"
        print("Google Places returned nothing; falling back to the fixture file.")
    return json.loads(FIXTURE.read_text("utf-8")), "fixture"


def places_search(query, key):
    """Google Places Text Search (New). Only used when GOOGLE_PLACES_KEY is set."""
    brand = next((b for b in ("adcb", "emiratesnbd", "aramex", "emiratespost", "uaepass", "tamm")
                  if b in query.lower().replace(" ", "")), "")
    try:
        r = httpx.post("https://places.googleapis.com/v1/places:searchText", timeout=15,
                       headers={"X-Goog-Api-Key": key,
                                "X-Goog-FieldMask": "places.displayName,places.formattedAddress,"
                                "places.internationalPhoneNumber,places.websiteUri,places.userRatingCount"},
                       json={"textQuery": query, "regionCode": "AE"})
        r.raise_for_status()
    except Exception as e:
        print(f"Places search failed for {query!r}: {type(e).__name__}")
        return []
    return [{"brand": brand, "name": (p.get("displayName") or {}).get("text", ""),
             "address": p.get("formattedAddress", ""),
             "phone": (p.get("internationalPhoneNumber") or "").replace(" ", ""),
             "website": p.get("websiteUri", ""), "review_count": p.get("userRatingCount", 0),
             "source": "google_places", "synthetic": False} for p in r.json().get("places", [])]


# ---------------------------------------------------------------- signals
def phone_check(api, number, brand_display):
    """Ask the API; never reimplement its rules."""
    if not number:
        return None, None, "The listing shows no phone number."
    r = httpx.post(api + "/check-number", json={"number": number, "brand_context": brand_display}, timeout=15)
    r.raise_for_status()
    d = r.json()
    official = any(x.get("code") == "official" for x in d.get("reasons") or [])
    texts = "; ".join(x.get("text", "") for x in d.get("reasons") or []
                      if x.get("text") and x.get("code") != "not_in_official_set")
    if official:
        sentence = f"The phone number {d.get('number', number)} is {brand_display}'s published helpline."
    else:
        sentence = f"The phone number {d.get('number', number)} is not one of {brand_display}'s published numbers" \
                   + (f" ({texts})." if texts else ".")
    return official, d.get("verdict"), sentence


def address_check(address, brand_rows, display):
    if not brand_rows:
        return None, "", f"No official branch list for {display} yet, so the address was not checked."
    lt = toks(address)
    best, best_score = None, 0.0
    for b in brand_rows:
        bt = toks(b["address"]) | toks(b["name"])
        if not bt:
            continue
        shared = lt & bt
        score = len(shared) / min(len(lt) or 1, len(bt))
        if len(shared) >= 2 and score > best_score:
            best, best_score = b, score
    if best and best_score >= 0.5:
        return True, best["name"], f"The address matches {display}'s official branch \"{best['name']}\"."
    return False, "", f"The address does not match any branch on {display}'s official branch list."


_last_osm = [0.0]

# Names a brand may be mapped under on OpenStreetMap.
OSM_NAMES = {"adcb": ["ADCB", "Abu Dhabi Commercial Bank"],
             "emiratesnbd": ["Emirates NBD"],
             "aramex": ["Aramex"],
             "emiratespost": ["Emirates Post", "NXN"],
             "uaepass": ["UAE PASS"],
             "tamm": ["TAMM"]}
CITIES = ("Dubai", "Abu Dhabi", "Sharjah", "Ajman", "Fujairah", "Al Ain",
          "Ras Al Khaimah", "Umm Al Quwain")


def _nominatim(q, email):
    OSM_CACHE.mkdir(parents=True, exist_ok=True)
    f = OSM_CACHE / (hashlib.sha1(q.encode()).hexdigest() + ".json")
    if f.exists():
        return json.loads(f.read_text("utf-8"))
    wait = 1.1 - (time.time() - _last_osm[0])          # usage policy: max 1 request/second
    if wait > 0:
        time.sleep(wait)
    params = {"q": q, "format": "jsonv2", "limit": 40, "countrycodes": "ae"}
    if email:
        params["email"] = email
    r = httpx.get("https://nominatim.openstreetmap.org/search", params=params,
                  headers={"User-Agent": UA}, timeout=15)
    _last_osm[0] = time.time()
    r.raise_for_status()
    results = r.json()
    f.write_text(json.dumps(results), "utf-8")
    return results


def osm_check(listing, display, email=""):
    """Is this brand mapped on OpenStreetMap at this address?
    True  = a mapped location of the brand matches the address
    False = the brand IS mapped in this city, but not at this address
    None  = OpenStreetMap has no locations for the brand here, so it can't confirm or deny"""
    addr = listing.get("address") or ""
    city = next((c for c in CITIES if c.lower() in addr.lower()), "")
    names = OSM_NAMES.get((listing.get("brand") or "").lower(), [display])
    results = []
    try:
        for n in names:
            results += _nominatim(f"{n} {city}".strip(), email)
    except Exception as e:
        return None, f"OpenStreetMap could not be checked ({type(e).__name__})."
    brand_toks = set().union(*(toks(n) for n in names)) or toks(display)
    mapped = [r for r in results if brand_toks & toks(f"{r.get('name', '')} {r.get('display_name', '')}")]
    if not mapped:
        return None, (f"OpenStreetMap has no mapped {display} locations{' in ' + city if city else ''}, "
                      "so it can neither confirm nor rule out this listing.")
    lt = toks(addr)
    for r in mapped:
        if len(lt & (toks(r.get("display_name")) - brand_toks)) >= 2:
            return True, f"OpenStreetMap shows a {display} location at this address."
    return False, (f"OpenStreetMap maps {len(mapped)} {display} location(s){' in ' + city if city else ''}, "
                   "but none at this address.")


def web_check(listing, key):
    if not key:
        return None, "Web footprint not checked (no search API key)."
    local = re.sub(r"^\+971", "0", listing.get("phone") or "")
    q = f"\"{listing.get('name', '')}\"" + (f" \"{local}\"" if local else "")
    try:
        r = httpx.get("https://api.search.brave.com/res/v1/web/search", params={"q": q, "count": 10},
                      headers={"X-Subscription-Token": key, "Accept": "application/json"}, timeout=15)
        r.raise_for_status()
        hits = [x for x in (r.json().get("web") or {}).get("results", [])
                if "google." not in urlparse(x.get("url", "")).netloc]
    except Exception as e:
        return None, f"Web footprint could not be checked ({type(e).__name__})."
    n = len(hits)
    if n >= 2:
        return n, f"The name and phone appear on {n} other websites."
    return n, f"The name and phone appear on almost no other websites ({n}), a sign of a fabricated listing."


def website_check(website, brand_row):
    if not website:
        return None, "The listing has no website."
    host = (urlparse(website if "://" in website else "https://" + website).hostname or "").lower()
    official = [d.strip().lower() for d in (brand_row.get("official_domains") or "").split(";") if d.strip()]
    if reg_of(host) in official:
        return True, f"The website {host} is an official {brand_row['display_name']} domain."
    return False, f"The website {host} is not an official {brand_row['display_name']} domain."


# ---------------------------------------------------------------- verdict
def decide(sig, phone_verdict, display):
    checked = {k: v for k, v in sig.items() if v is not None}
    disagree = [k for k, v in checked.items() if v is False]
    agree = [k for k, v in checked.items() if v is True]
    n = len(disagree)
    if phone_verdict == "malicious":
        return n, "fabricated", (f"Conclusively fabricated: {display} does not publish a personal mobile number "
                                 "as a customer service line.")
    if n >= 3:
        return n, "fabricated", (f"Conclusively fabricated: {n} independent checks disagree with "
                                 f"{display}'s official information.")
    if n == 0 and ("phone_in_official" in agree or "address_in_branches" in agree):
        return n, "genuine", f"Consistent with {display}'s official information on every check made."
    if disagree == ["found_in_osm"] and "phone_in_official" in agree:
        return n, "genuine", (f"The phone is {display}'s published helpline. It is missing from OpenStreetMap, "
                              "but map coverage in the UAE is incomplete, so that alone is not a warning sign.")
    if n == 0:
        return n, "unverified", "Nothing contradicts this listing, but not enough could be checked to clear it."
    return n, "suspicious", f"{n} check(s) disagree with {display}'s official information. Call the number on {display}'s own website instead."


def scan(api, places_key="", brave_key="", email=""):
    brands, branches = load_refs()
    listings, source = load_listings(places_key)
    rows = []
    for L in listings:
        brand = (L.get("brand") or "").lower()
        b = brands.get(brand, {"display_name": brand or "the brand", "official_domains": ""})
        display = b["display_name"]

        phone_ok, phone_verdict, s_phone = phone_check(api, L.get("phone"), display)
        addr_ok, match, s_addr = address_check(L.get("address"), branches.get(brand, []), display)
        osm_ok, s_osm = osm_check(L, display, email)
        web_n, s_web = web_check(L, brave_key)
        site_ok, s_site = website_check(L.get("website"), b)

        sig = {"phone_in_official": phone_ok, "address_in_branches": addr_ok, "found_in_osm": osm_ok,
               "web_mentions": None if web_n is None else web_n >= 2, "website_official": site_ok}
        n, verdict, summary = decide(sig, phone_verdict, display)
        reasons = [summary, s_phone, s_addr, s_osm, s_web, s_site]
        rc = L.get("review_count")
        if rc is not None and int(rc or 0) < 5:
            rc = int(rc or 0)
            reasons.append("The listing has no reviews." if rc == 0 else
                           f"The listing has only {rc} review{'s' if rc != 1 else ''}.")

        fmt = lambda v: "" if v is None else str(v).lower()
        rows.append({"brand": brand, "name": L.get("name", ""), "phone": L.get("phone", ""),
                     "phone_in_official": fmt(phone_ok), "address_in_branches": fmt(addr_ok),
                     "found_in_osm": fmt(osm_ok), "web_mentions": "" if web_n is None else web_n,
                     "disagreement_count": n, "verdict": verdict,
                     "website_official": fmt(site_ok), "phone_verdict": phone_verdict or "",
                     "matched_branch": match, "reasons": " | ".join(r for r in reasons if r),
                     "synthetic": str(bool(L.get("synthetic"))).lower(),
                     "source": L.get("source", source)})
    return rows


def main():
    import os
    ap = argparse.ArgumentParser(description="Cross-check maps listings against official brand data.")
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    a = ap.parse_args()
    api = a.api.rstrip("/")
    try:
        httpx.get(api + "/docs", timeout=5)
    except Exception:
        sys.exit(f"Could not reach the API at {api}. Start it with: uvicorn api:app --port 8000")
    rows = scan(api, os.environ.get("GOOGLE_PLACES_KEY", ""), os.environ.get("BRAVE_API_KEY", ""),
                os.environ.get("NOMINATIM_EMAIL", ""))
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    for r in rows:
        print(f"{r['verdict']:<11} disagree={r['disagreement_count']}  {r['brand']:<12} {r['name']}")
    print(f"\n{len(rows)} listings -> {OUT}")


if __name__ == "__main__":
    main()
