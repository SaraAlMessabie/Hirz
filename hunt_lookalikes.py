"""
Generate look-alike domains for protected brands, find the registered ones.
  out: data/lookalikes.csv   (written as it goes - safe to interrupt)
"""
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import dnstwist
import pandas as pd

BRANDS = ["adcb.com", "emiratesnbd.com", "aramex.com",
          "uaepass.ae", "dhl.com", "emiratespost.ae"]
OUT = "data/lookalikes.csv"

_r = dns.resolver.Resolver()
_r.timeout = _r.lifetime = 3
_r.nameservers = ["1.1.1.1", "8.8.8.8"]

def probe(item):
    brand, domain, fuzzer = item
    try:
        _r.resolve(domain, "A")
    except Exception:
        return None
    try:
        mx = len(_r.resolve(domain, "MX"))
    except Exception:
        mx = 0
    return {"brand": brand, "domain": domain, "fuzzer": fuzzer,
            "has_mx": int(mx > 0), "mx_count": mx}

def save(hits):
    if hits:
        pd.DataFrame(hits).drop_duplicates("domain").to_csv(OUT, index=False)

if __name__ == "__main__":
    cands = set()
    for b in BRANDS:
        fz = dnstwist.Fuzzer(b)
        fz.generate()
        for d in fz.domains:
            name = d.get("domain")
            if name and name != b:
                cands.add((b, name, d.get("fuzzer", "")))
    cands = list(cands)
    print(f"{len(cands)} permutations across {len(BRANDS)} brands")

    hits, done, t0 = [], 0, time.time()
    try:
        with ThreadPoolExecutor(max_workers=60) as pool:
            for fut in as_completed({pool.submit(probe, c): c for c in cands}):
                r = fut.result(); done += 1
                if r: hits.append(r)
                if done % 500 == 0:
                    rate = done / max(time.time() - t0, 1)
                    save(hits)                       # <- write as we go
                    print(f"  {done}/{len(cands)}  registered {len(hits)}  "
                          f"{rate:.0f}/s  ETA {(len(cands)-done)/max(rate,1)/60:.1f}m")
    except KeyboardInterrupt:
        print("\ninterrupted - saving what we have")

    save(hits)
    if not hits:
        print("no registered look-alikes found"); raise SystemExit

    df = pd.DataFrame(hits).drop_duplicates("domain") \
           .sort_values(["has_mx", "brand"], ascending=[False, True])
    df.to_csv(OUT, index=False)

    print(f"\n{len(df)} registered look-alikes -> {OUT}")
    print(f"with MX records (ready to send phishing): {df.has_mx.sum()}")
    print("\nby brand:\n", df.groupby("brand").size().to_string())
    mx = df[df.has_mx == 1]
    if len(mx):
        print("\nMX-enabled (campaign being prepared):\n",
              mx[["brand","domain","fuzzer"]].head(20).to_string(index=False))