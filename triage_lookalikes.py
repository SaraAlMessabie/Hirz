"""
Triage look-alikes: registration age + verdict. Noise in, candidates out.
  out: data/lookalikes_triaged.csv
"""
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx, pandas as pd

from tier2 import rdap_features

API = "http://127.0.0.1:8000/check"


def enrich(domain):
    rd = rdap_features(domain)
    try:
        v = httpx.post(API, json={"url": domain, "deep": False}, timeout=20).json()
    except Exception:
        v = {}
    return {"domain": domain,
            "age_bucket": rd["age_bucket"], "rdap_found": rd["rdap_found"],
            "ns_count": rd["ns_count"],
            "score": v.get("score"), "verdict": v.get("verdict")}


if __name__ == "__main__":
    df = pd.read_csv("data/lookalikes.csv")
    print(f"triaging {len(df)} look-alikes")

    rows, done, t0 = [], 0, time.time()
    with ThreadPoolExecutor(max_workers=12) as pool:
        for f in as_completed({pool.submit(enrich, d): d for d in df.domain}):
            rows.append(f.result()); done += 1
            if done % 25 == 0:
                print(f"  {done}/{len(df)}  {done/max(time.time()-t0,1):.1f}/s")

    out = df.merge(pd.DataFrame(rows), on="domain", how="left")
    out.to_csv("data/lookalikes_triaged.csv", index=False)

    young = out[(out.age_bucket >= 0) & (out.age_bucket <= 3)]
    print(f"\n{len(out)} total -> {len(young)} registered within the last year")
    print(f"   of those, with MX: {young.has_mx.sum()}")
    print("\nby brand:\n", young.groupby("brand").size().to_string())
    print("\ntop candidates:\n",
          young.sort_values(["age_bucket", "has_mx"], ascending=[True, False])
               .head(20)[["brand", "domain", "fuzzer", "age_bucket", "has_mx", "score"]]
               .to_string(index=False))
