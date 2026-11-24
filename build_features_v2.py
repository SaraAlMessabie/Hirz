"""
crt.sh enrichment - resumable, writes partial results.
  python enrich_crtsh.py          # all domains
  python enrich_crtsh.py 600      # first 600 (stratified) - unblocks the retrain
"""
import json, pathlib, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx, pandas as pd, tldextract

CACHE = pathlib.Path("cache/crtsh"); CACHE.mkdir(parents=True, exist_ok=True)
OUT   = pathlib.Path("data/crtsh.csv")
UA = {"User-Agent": "Mozilla/5.0 (compatible; scam-detect-research/0.1)"}
FREE_CA = ("let's encrypt", "zerossl", "google trust", "buypass", "actalis")

def reg(host):
    e = tldextract.extract(host)
    return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else host

def fetch(domain):
    f = CACHE / f"{domain}.json"
    if f.exists():
        try: return json.loads(f.read_text("utf-8"))
        except Exception: pass
    for attempt in range(2):
        try:
            r = httpx.get("https://crt.sh/", params={"q": domain, "output": "json"},
                          timeout=20, headers=UA)
            if r.status_code == 200:
                data = r.json() if r.text.strip() else []
                f.write_text(json.dumps(data), "utf-8")
                return data
        except Exception:
            time.sleep(1)
    return None

def summarise(domain):
    certs = fetch(domain)
    if certs is None:
        return {"domain": domain, "ct_found": 0, "ct_cert_count": 0,
                "ct_first_seen": "", "ct_free_ca": 0, "ct_max_san": 0}
    firsts  = sorted(c.get("not_before","") for c in certs if c.get("not_before"))
    issuers = " ".join(c.get("issuer_name","").lower() for c in certs)
    max_san = max((len(set(c.get("name_value","").split("\n"))) for c in certs), default=0)
    return {"domain": domain,
            "ct_found": int(bool(certs)),
            "ct_cert_count": len(certs),
            "ct_first_seen": firsts[0][:10] if firsts else "",
            "ct_free_ca": int(any(ca in issuers for ca in FREE_CA)),
            "ct_max_san": max_san}

if __name__ == "__main__":
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None

    df = pd.read_csv("data/dataset.csv")
    df["reg"] = df["host"].map(reg)
    if limit:                                   # keep both classes represented
        keep = (df.groupby("label", group_keys=False)
                  .apply(lambda g: g.head(limit // 2)))
        domains = sorted(set(keep["reg"]))
    else:
        domains = sorted(set(df["reg"]))

    cached = sum((CACHE / f"{d}.json").exists() for d in domains)
    print(f"{len(domains)} domains  |  {cached} already cached  |  "
          f"{len(domains)-cached} to fetch")

    rows, done, t0 = [], 0, time.time()
    try:
        with ThreadPoolExecutor(max_workers=10) as pool:
            futs = {pool.submit(summarise, d): d for d in domains}
            for fut in as_completed(futs):
                rows.append(fut.result()); done += 1
                if done % 25 == 0 or done == len(domains):
                    rate = done / max(time.time() - t0, 1)
                    eta  = (len(domains) - done) / max(rate, 0.01) / 60
                    print(f"  {done}/{len(domains)}   {rate:.1f}/s   ETA {eta:.1f} min")
    except KeyboardInterrupt:
        print("\ninterrupted - writing what we have")

    out = pd.DataFrame(rows)
    if OUT.exists():                            # merge with any earlier run
        out = (pd.concat([pd.read_csv(OUT), out])
                 .drop_duplicates("domain", keep="last"))
    out.to_csv(OUT, index=False)

    print(f"\nwrote {OUT}  ({len(out)} domains)")
    print(f"found in CT: {out.ct_found.sum()} / {len(out)}")
    if out.ct_found.sum():
        print(out[out.ct_found == 1][["ct_cert_count","ct_free_ca","ct_max_san"]]
                .mean().round(2).to_string())