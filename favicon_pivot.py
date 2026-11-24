"""
Favicon hash pivoting.
Kits reuse the favicon verbatim, so one hash finds every deployment -
including brands we never listed.
  out: data/favicon_clusters.csv
"""
import base64, time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx, pandas as pd

try:
    import mmh3
    HAVE_MMH3 = True
except ImportError:
    import hashlib
    HAVE_MMH3 = False
    print("mmh3 not installed - falling back to sha256 "
          "(works for local clustering, not for urlscan/Shodan search)")

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"}


def favicon_hash(domain):
    """The integer format urlscan.io and Shodan index on."""
    for scheme in ("https", "http"):
        try:
            r = httpx.get(f"{scheme}://{domain}/favicon.ico",
                          timeout=8, headers=UA, follow_redirects=True)
            if r.status_code != 200 or len(r.content) < 60:
                continue
            if HAVE_MMH3:
                return mmh3.hash(base64.encodebytes(r.content))
            return int(hashlib.sha256(r.content).hexdigest()[:15], 16)
        except Exception:
            continue
    return None


if __name__ == "__main__":
    frames = []
    for path in ("data/ct_hits.csv", "data/lookalikes_triaged.csv"):
        try:
            frames.append(pd.read_csv(path)[["domain", "brand"]])
        except Exception:
            pass
    if not frames:
        raise SystemExit("no detection files found")

    df = pd.concat(frames).drop_duplicates("domain")
    print(f"hashing favicons for {len(df)} domains")

    got, done, t0 = {}, 0, time.time()
    with ThreadPoolExecutor(max_workers=20) as pool:
        futs = {pool.submit(favicon_hash, r.domain): r for r in df.itertuples()}
        for f in as_completed(futs):
            h = f.result(); done += 1
            if h is not None:
                got[futs[f].domain] = (h, futs[f].brand)
            if done % 50 == 0:
                print(f"  {done}/{len(df)}  got {len(got)}  "
                      f"{done/max(time.time()-t0,1):.1f}/s")

    groups = defaultdict(list)
    for dom, (h, brand) in got.items():
        groups[h].append((dom, brand))

    rows = []
    for h, members in groups.items():
        if len(members) < 2:
            continue
        brands = sorted({b for _, b in members if isinstance(b, str)})
        rows.append({"favicon_hash": h, "deployments": len(members),
                     "brands_impersonated": len(brands),
                     "brands": ";".join(brands),
                     "domains": ";".join(sorted(d for d, _ in members))})

    out = pd.DataFrame(rows).sort_values("deployments", ascending=False) \
          if rows else pd.DataFrame(columns=["favicon_hash", "deployments"])
    out.to_csv("data/favicon_clusters.csv", index=False)

    print(f"\n{len(got)} favicons retrieved -> {len(out)} kit clusters")
    if len(out):
        print(out.head(10)[["favicon_hash", "deployments",
                            "brands_impersonated", "brands"]].to_string(index=False))
        top = out.iloc[0]
        print(f"\nLargest kit: hash {top.favicon_hash} on {top.deployments} domains "
              f"across {top.brands_impersonated} brands.")
        print("Search it internet-wide:  "
              f"urlscan.io  ->  page.favicon_hash:{top.favicon_hash}")
