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

HOURS_BACK = 8760
API = "http://127.0.0.1:8000/check"

TERMS = ["adcb", "emiratesnbd", "aramex", "uaepass", "emiratespost",
         "dhl", "fedex", "paypal", "netflix", "whatsapp"]

# the brand's real domain - a cert covering it belongs to the brand
REAL = {"paypal": "paypal.com", "dhl": "dhl.com", "fedex": "fedex.com",
        "netflix": "netflix.com", "whatsapp": "whatsapp.com",
        "aramex": "aramex.com", "adcb": "adcb.com",
        "emiratesnbd": "emiratesnbd.com", "uaepass": "uaepass.ae",
        "emiratespost": "emiratespost.ae"}

FREE_HOSTS = ("pages.dev", "web.app", "firebaseapp.com", "workers.dev",
              "netlify.app", "github.io", "vercel.app", "r2.dev",
              "glitch.me", "repl.co", "000webhostapp.com")

FREE_CA = ("let's encrypt", "zerossl", "google trust", "buypass", "actalis")

def reg_of(host):
    e = tldextract.extract(host)
    return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else host

def is_brand_own(reg, term):
    """aramex.com / aramex.ae -> real brand.  aramex-delivery.xyz -> not."""
    return tldextract.extract(reg).domain == term

def cert_covers_real_brand(cert, term):
    """A cert covering paypal.com AND paypal-survey.com was issued by PayPal."""
    names = {n.strip().lstrip("*.").lower()
             for n in (cert.get("name_value") or "").split("\n")}
    real = REAL.get(term)
    return bool(real) and any(n == real or n.endswith("." + real) for n in names)

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
                          params={"q": pattern, "output": "json",
                                  "exclude": "expired"})
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
        return httpx.post(API, json={"url": domain}, timeout=20).json()
    except Exception:
        return {}

def scan():
    seen, public = load_seen(), known_public()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=HOURS_BACK)
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = []

    for term in TERMS:
        n_certs = n_recent = n_own = n_new = 0
        dates = []

        for pattern in (f"%{term}-%", f"%-{term}%", f"%{term}%"):
            for c in query(pattern):
                n_certs += 1
                nb = (c.get("not_before") or "")[:19]
                try:
                    issued = datetime.fromisoformat(nb).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
                dates.append(issued)
                if issued < cutoff:
                    continue
                n_recent += 1

                # the brand issued this cert for itself
                if cert_covers_real_brand(c, term):
                    n_own += 1
                    continue

                issuer = (c.get("issuer_name") or "")
                free_ca = int(any(ca in issuer.lower() for ca in FREE_CA))

                for name in set((c.get("name_value") or "").split("\n")):
                    name = name.strip().lstrip("*.").lower()
                    if not name or term not in name:
                        continue
                    # on free hosting the subdomain IS the site
                    reg = name if name.endswith(FREE_HOSTS) else reg_of(name)
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
                        "age_bucket": (v.get("enrichment") or {}).get("age_bucket", ""),
                        "free_ca": free_ca, "issuer": issuer[:60],
                    })

            # write as we go so an interrupt doesn't lose the scan
            if rows:
                _d = pd.DataFrame(rows)
                if OUT.exists():
                    _d = (pd.concat([pd.read_csv(OUT), _d])
                            .drop_duplicates("domain", keep="first"))
                _d.to_csv(OUT, index=False)
            time.sleep(3)

        span = f"{min(dates).date()}..{max(dates).date()}" if dates else "none"
        print(f"  {term:14} certs {n_certs:>6}  recent {n_recent:>5}  "
              f"own {n_own:>5}  NEW {n_new:>4}   {span}")

    SEEN.write_text(json.dumps(sorted(seen)), "utf-8")
    if not rows:
        print("\nno new domains this scan"); return

    df = pd.read_csv(OUT)
    print(f"\n{len(rows)} new  |  {len(df)} total -> {OUT}")
    print(f"NOT yet in any public feed: {(df.already_in_public_feed == 0).sum()}")
    print("\n" + df.sort_values("score", ascending=False)
                   .head(15)[["brand","domain","cert_issued","score","verdict","free_ca"]]
                   .to_string(index=False))

if __name__ == "__main__":
    if "--watch" in sys.argv:
        while True:
            print(f"\n=== scan {datetime.now().strftime('%H:%M:%S')} ===")
            scan()
            time.sleep(300)
    else:
        scan()