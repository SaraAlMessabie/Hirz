"""
RDAP enrichment via the IANA bootstrap - queries each TLD's real registry.
  python enrich_rdap.py          # all
  python enrich_rdap.py 600      # subset
"""
import json, pathlib, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import httpx, pandas as pd, tldextract

CACHE = pathlib.Path("cache/rdap"); CACHE.mkdir(parents=True, exist_ok=True)
OUT = pathlib.Path("data/rdap.csv")
UA = {"User-Agent": "Mozilla/5.0 (compatible; scam-detect-research/0.1)",
      "Accept": "application/rdap+json"}

purged = 0
for f in CACHE.glob("*.json"):
    try:
        d = json.loads(f.read_text("utf-8"))
        if d.get("_notfound") in (429, 403) or "_error" in d:
            f.unlink(); purged += 1
    except Exception:
        f.unlink(); purged += 1
print(f"purged {purged} bad cache entries")

BOOT = {}
_raw = httpx.get("https://data.iana.org/rdap/dns.json", timeout=30, headers=UA).json()
for tlds, urls in _raw["services"]:
    for t in tlds:
        BOOT[t.lower()] = urls[0].rstrip("/")
print(f"bootstrap: {len(BOOT)} TLDs")


def reg(host):
    e = tldextract.extract(host)
    return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else host


def fetch(domain):
    f = CACHE / f"{domain}.json"
    if f.exists():
        try: return json.loads(f.read_text("utf-8"))
        except Exception: pass
    base = BOOT.get(domain.rsplit(".", 1)[-1])
    if not base:
        return {"_notfound": "no_rdap_for_tld"}
    try:
        r = httpx.get(f"{base}/domain/{domain}", timeout=15,
                      headers=UA, follow_redirects=True)
        if r.status_code == 200:
            d = r.json(); f.write_text(json.dumps(d), "utf-8"); return d
        if r.status_code == 404:
            d = {"_notfound": 404}; f.write_text(json.dumps(d), "utf-8"); return d
        return {"_notfound": r.status_code}
    except Exception as e:
        return {"_error": e.__class__.__name__}


def days_since(iso):
    try:
        return (datetime.now(timezone.utc)
                - datetime.fromisoformat(iso.replace("Z", "+00:00"))).days
    except Exception:
        return None


def summarise(domain):
    d = fetch(domain)
    base = {"domain": domain, "rdap_found": 0, "age_days": -1,
            "expiry_days": -1, "ns_count": 0}
    if not isinstance(d, dict) or "events" not in d:
        return base
    created = expires = None
    for ev in d.get("events") or []:
        a = (ev.get("eventAction") or "").lower()
        if a == "registration": created = ev.get("eventDate")
        if a == "expiration":   expires = ev.get("eventDate")
    base.update(rdap_found=1,
                age_days=days_since(created) if created else -1,
                expiry_days=-(days_since(expires)) if expires else -1,
                ns_count=len(d.get("nameservers") or []))
    return base


if __name__ == "__main__":
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    df = pd.read_csv("data/dataset.csv"); df["reg"] = df["host"].map(reg)
    domains = sorted(set(df["reg"]))
    if limit:
        domains = domains[:limit]

    rows, done, t0 = [], 0, time.time()
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            for fut in as_completed({pool.submit(summarise, d): d for d in domains}):
                rows.append(fut.result()); done += 1
                if done % 50 == 0 or done == len(domains):
                    rate = done / max(time.time() - t0, 1)
                    found = sum(r["rdap_found"] for r in rows)
                    print(f"  {done}/{len(domains)}  found {found}  "
                          f"{rate:.1f}/s  ETA {(len(domains)-done)/max(rate,.01)/60:.1f}m")
    except KeyboardInterrupt:
        print("\ninterrupted - writing partial")

    out = pd.DataFrame(rows)
    if OUT.exists():
        out = pd.concat([pd.read_csv(OUT), out]).drop_duplicates("domain", keep="last")
    out.to_csv(OUT, index=False)
    ok = out[out.rdap_found == 1]
    print(f"\nwrote {OUT} | found {len(ok)}/{len(out)} ({100*len(ok)/max(len(out),1):.0f}%)")
