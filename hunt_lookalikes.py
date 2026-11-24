"""
Generate look-alike domains for protected brands, find the registered ones.
  out: data/lookalikes.csv
"""
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import dnstwist
import pandas as pd

BRANDS = ["adcb.com", "emiratesnbd.com", "aramex.com",
          "uaepass.ae", "dhl.com", "emiratespost.ae"]

_r = dns.resolver.Resolver()
_r.timeout = _r.lifetime = 3
_r.nameservers = ["1.1.1.1", "8.8.8.8"]

def probe(item):
    brand, domain, fuzzer = item
    try:
        _r.resolve(domain, "A")
    except Exception:
        return None                      # not registered / not resolving
    try:
        mx = len(_r.resolve(domain, "MX"))
    except Exception:
        mx = 0
    return {"brand": brand, "domain": domain, "fuzzer": fuzzer,
            "has_mx": int(mx > 0), "mx_count": mx}

if __name__ == "__main__":
    candidates = []
    for b in BRANDS:
        fz = dnstwist.Fuzzer(b)
        fz.generate()
        for d in fz.domains:
            name = d.get("domain")
            if name and name != b:
                candidates.append((b, name, d.get("fuzzer", "")))
    candidates = list({(b, d, f) for b, d, f in candidates})
    print(f"{len(candidates)} permutations across {len(BRANDS)} brands")

    hits, done, t0 = [], 0, time.time()
    with ThreadPoolExecutor(max_workers=60) as pool:
        for fut in as_completed({pool.submit(probe, c): c for c in candidates}):
            r = fut.result(); done += 1
            if r: hits.append(r)
            if done % 500 == 0:
                rate = done / max(time.time() - t0, 1)
                print(f"  {done}/{len(candidates)}  registered {len(hits)}  "
                      f"{rate:.0f}/s  ETA {(len(candidates)-done)/max(rate,1)/60:.1f}m")

    df = pd.DataFrame(hits).sort_values(["has_mx", "brand"], ascending=[False, True])
    df.to_csv("data/lookalikes.csv", index=False)

    print(f"\n{len(df)} registered look-alikes -> data/lookalikes.csv")
    print(f"with MX records (ready to send phishing): {df.has_mx.sum()}")
    print("\nby brand:\n", df.groupby("brand").size().to_string())
    print("\ntop MX-enabled:\n",
          df[df.has_mx == 1][["brand","domain","fuzzer"]].head(15).to_string(index=False))