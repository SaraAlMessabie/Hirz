"""
Certificate Transparency watcher.
  python ct_watch.py           # one scan
  python ct_watch.py --watch   # loop every 5 minutes
"""
import json, pathlib, sys, time
from datetime import datetime, timedelta, timezone

import httpx, pandas as pd, tldextract

OUT  = pathlib.Path("data/ct_hits.csv")
SEEN = pathlib.Path("data/ct_seen.json")
UA = {"User-Agent": "Mozilla/5.0 (compatible; scam-detect-research/0.1)"}

HOURS_BACK = 720
API = "http://127.0.0.1:8000/check"

TERMS = ["adcb", "emiratesnbd", "aramex", "uaepass", "emiratespost",
         "dhl", "fedex", "paypal", "netflix", "whatsapp"]

def reg_of(host):
    e = tldextract.extract(host)
    return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else host

def is_brand_own(reg, term):
    """aramex.com / aramex.ae / aramex.co.uk -> the real brand.
       aramex-delivery.xyz / secure-aramex.com -> not."""
    return tldextract.extract(reg).domain == term

def load_seen():
    if SEEN.exists():
        try: return set(json.loads(SEEN.read_text("utf-8")))
        except Exception: pass
    return set()

def known_public():
    out = set()
    for name in ["openphish.txt", "phishdb.txt"]:
        p = pathlib.Path("data/raw") / name
        if p.exists():
            for line in p.read_text("utf-8", errors="ignore").splitlines():
                h = line.split("//")[-1].split("/")[0].strip().lower()
                if h: out.add(reg_of(h))
    return out

def query(pattern, tries=3):
    for i in range(tries):
        try:
            r = httpx.get("https://crt.sh/", headers=UA, timeout=60,
                          params={"q": pattern, "output": "json"})
            if r.status_code == 200 and r.text.strip():
                return r.json()
            if r.status_code in (502, 503):
                time.sleep(4 * (i + 1)); continue
            return []
        except Exception:
            time.sleep(4 * (i + 1))
    return []

def score(domain):
    try:
        return httpx.post(API, json={"url": domain}, timeout=10).json()
    except Exception:
        return {}

def scan():
    seen, public = load_seen(), known_public()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=HOURS_BACK)
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = []

    for term in TERMS:
        n_certs = n_recent = n_own = n_new = 0
        # hyphen patterns catch look-alikes, not the brand's own infrastructure
        for pattern in (f"%{term}-%", f"%-{term}%", f"%{term}%"):
            for c in query(pattern):
                n_certs += 1
                nb = (c.get("not_before") or "")[:19]
                try:
                    issued = datetime.fromisoformat(nb).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
                if issued < cutoff:
                    continue
                n_recent += 1

                for name in set((c.get("name_value") or "").split("\n")):
                    name = name.strip().lstrip("*.").lower()
                    if not name or term not in name:
                        continue
                    reg = reg_of(name)
                    if is_brand_own(reg, term):
                        n_own += 1; continue
                    if reg in seen:
                        continue

                    seen.add(reg); n_new += 1
                    v = score(reg)
                    rows.append({
                        "brand": term, "domain": reg, "sample_host": name,
                        "cert_issued": issued.isoformat(timespec="seconds"),
                        "first_seen_by_us": now_iso,
                        "already_in_public_feed": int(reg in public),
                        "score": v.get("score", ""), "verdict": v.get("verdict", ""),
                        "issuer": (c.get("issuer_name") or "")[:60],
                    })
            time.sleep(3)

        print(f"  {term:14} certs {n_certs:>6}  recent {n_recent:>5}  "
              f"brand-own {n_own:>5}  NEW {n_new:>4}")

    SEEN.write_text(json.dumps(sorted(seen)), "utf-8")
    if not rows:
        print("\nno new domains this scan"); return

    df = pd.DataFrame(rows).sort_values("score", ascending=False)
    if OUT.exists():
        df = pd.concat([pd.read_csv(OUT), df]).drop_duplicates("domain", keep="first")
    df.to_csv(OUT, index=False)

    print(f"\n{len(rows)} new  |  {len(df)} total -> {OUT}")
    print(f"NOT yet in any public feed: {(df.already_in_public_feed == 0).sum()}")
    print("\n" + df.head(15)[["brand","domain","cert_issued","score","verdict"]]
                    .to_string(index=False))

if __name__ == "__main__":
    if "--watch" in sys.argv:
        while True:
            print(f"\n=== scan {datetime.now().strftime('%H:%M:%S')} ===")
            scan()
            time.sleep(300)
    else:
        scan()