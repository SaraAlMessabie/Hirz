"""
Campaign clustering that works behind Cloudflare.
IP clustering fails when everything shares a CDN. These do not:
  - registration time  (scammers register in batches)
  - nameservers        (same DNS account across a campaign)
  - hosting ASN        (concentration analysis)
  out: data/campaign_clusters.csv, data/asn_concentration.csv
"""
import json, pathlib, time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import dns.resolver, httpx, pandas as pd, tldextract

CACHE = pathlib.Path("cache/rdap")
_r = dns.resolver.Resolver(); _r.timeout = _r.lifetime = 3
_r.nameservers = ["1.1.1.1", "8.8.8.8"]


def reg_of(h):
    e = tldextract.extract(h)
    return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else h


def rdap_detail(domain):
    """Registration timestamp + nameservers, from the cache we already built."""
    f = CACHE / f"{domain}.json"
    if not f.exists():
        return None, []
    try:
        d = json.loads(f.read_text("utf-8"))
    except Exception:
        return None, []
    created = None
    for ev in d.get("events") or []:
        if (ev.get("eventAction") or "").lower() == "registration":
            created = ev.get("eventDate")
    ns = sorted({(n.get("ldhName") or "").lower()
                 for n in (d.get("nameservers") or []) if n.get("ldhName")})
    return created, ns


def ip_of(d):
    try:
        return str(_r.resolve(d, "A")[0])
    except Exception:
        return None


def asn_of(ip):
    try:
        r = httpx.get(f"https://api.iptoasn.com/v1/as/ip/{ip}", timeout=8)
        if r.status_code == 200:
            j = r.json()
            return j.get("as_number"), (j.get("as_description") or "")[:48]
    except Exception:
        pass
    return None, ""


if __name__ == "__main__":
    frames = []
    for path in ("data/ct_hits.csv", "data/lookalikes_triaged.csv"):
        try:
            frames.append(pd.read_csv(path)[["domain", "brand"]])
        except Exception:
            pass
    df = pd.concat(frames).drop_duplicates("domain")
    df["reg"] = df.domain.map(reg_of)
    print(f"clustering {len(df)} domains\n")

    # ---- registration time + nameservers (free, from cache) --------
    by_hour, by_ns = defaultdict(list), defaultdict(list)
    dated = 0
    for r in df.itertuples():
        created, ns = rdap_detail(r.reg)
        if created:
            dated += 1
            try:
                hour = datetime.fromisoformat(
                    created.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:00")
                by_hour[hour].append(r.domain)
            except Exception:
                pass
        for n in ns:
            by_ns[n].append(r.domain)
    print(f"registration dates available for {dated}/{len(df)} domains")

    rows = []
    for hour, doms in by_hour.items():
        if len(set(doms)) >= 3:
            rows.append({"pivot": "registered_same_hour", "key": hour,
                         "size": len(set(doms)),
                         "domains": ";".join(sorted(set(doms))[:25])})
    for ns, doms in by_ns.items():
        if len(set(doms)) >= 3:
            rows.append({"pivot": "shared_nameserver", "key": ns,
                         "size": len(set(doms)),
                         "domains": ";".join(sorted(set(doms))[:25])})

    out = (pd.DataFrame(rows).sort_values("size", ascending=False)
           if rows else pd.DataFrame(columns=["pivot", "key", "size", "domains"]))
    out.to_csv("data/campaign_clusters.csv", index=False)
    print(f"\n{len(out)} campaign clusters -> data/campaign_clusters.csv")
    if len(out):
        print(out.head(12)[["pivot", "key", "size"]].to_string(index=False))

    # ---- ASN concentration ----------------------------------------
    print("\nresolving hosting ASNs...")
    ips, done = {}, 0
    with ThreadPoolExecutor(max_workers=30) as pool:
        futs = {pool.submit(ip_of, d): d for d in df.domain}
        for f in as_completed(futs):
            ip = f.result(); done += 1
            if ip:
                ips[futs[f]] = ip
    print(f"  {len(ips)}/{len(df)} resolved")

    uniq_ips = sorted(set(ips.values()))
    asns = {}
    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = {pool.submit(asn_of, ip): ip for ip in uniq_ips}
        for f in as_completed(futs):
            asns[futs[f]] = f.result()

    counts = defaultdict(lambda: [0, ""])
    for dom, ip in ips.items():
        num, desc = asns.get(ip, (None, ""))
        if num:
            counts[num][0] += 1
            counts[num][1] = desc

    arows = [{"asn": k, "name": v[1], "domains": v[0]}
             for k, v in counts.items()]
    a = (pd.DataFrame(arows).sort_values("domains", ascending=False)
         if arows else pd.DataFrame(columns=["asn", "name", "domains"]))
    a.to_csv("data/asn_concentration.csv", index=False)

    if len(a):
        total = int(a.domains.sum())
        top4 = int(a.head(4).domains.sum())
        print(f"\nASN concentration -> data/asn_concentration.csv")
        print(a.head(8).to_string(index=False))
        print(f"\nTop 4 autonomous systems host {top4}/{total} "
              f"({100*top4/max(total,1):.0f}%) of everything we found.")
