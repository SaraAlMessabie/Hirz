"""
Confirmed bad domain -> pivots -> siblings and predicted future domains.
  out: data/campaigns.csv, data/predicted.csv
"""
import re, socket, ssl, time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver, pandas as pd, tldextract

TERMS = ["adcb","emiratesnbd","aramex","uaepass","emiratespost",
         "dhl","fedex","paypal","netflix","whatsapp"]

_r = dns.resolver.Resolver(); _r.timeout = _r.lifetime = 3
_r.nameservers = ["1.1.1.1", "8.8.8.8"]

def reg_of(h):
    e = tldextract.extract(h)
    return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else h

def ip_of(d):
    try:    return str(_r.resolve(d, "A")[0])
    except Exception: return None

def sans_of(d):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((d, 443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=d) as ss:
                c = ss.getpeercert()
        return sorted({v.lstrip("*.").lower()
                       for k, v in c.get("subjectAltName", ()) if k == "DNS"})
    except Exception:
        return []

def template_of(domain, term):
    """dhl-smartmail.net + dhl -> {brand}-smartmail.net"""
    return domain.replace(term, "{brand}", 1) if term in domain else None

if __name__ == "__main__":
    df = pd.read_csv("data/ct_hits.csv")
    bad = df[pd.to_numeric(df.score, errors="coerce").fillna(0) >= 50]
    if bad.empty:
        bad = df
    print(f"pivoting from {len(bad)} domains\n")

    # ---- enrich -------------------------------------------------
    facts = {}
    with ThreadPoolExecutor(max_workers=25) as pool:
        futs = {pool.submit(lambda d: (d, ip_of(d), sans_of(d)), r.domain): r
                for r in bad.itertuples()}
        for f in as_completed(futs):
            d, ip, sans = f.result()
            facts[d] = {"ip": ip, "sans": sans,
                        "brand": futs[f].brand}

    # ---- cluster by shared infrastructure -----------------------
    by_ip, by_san = defaultdict(list), defaultdict(list)
    for d, v in facts.items():
        if v["ip"]: by_ip[v["ip"]].append(d)
        for s in v["sans"]:
            by_san[s].append(d)

    clusters = []
    for ip, doms in by_ip.items():
        if len(doms) > 1:
            clusters.append({"pivot": "shared_ip", "key": ip,
                             "size": len(doms), "domains": ";".join(sorted(doms))})
    for san, doms in by_san.items():
        if len(set(doms)) > 1:
            clusters.append({"pivot": "shared_cert", "key": san,
                             "size": len(set(doms)), "domains": ";".join(sorted(set(doms)))})

    cl = pd.DataFrame(clusters).sort_values("size", ascending=False) \
         if clusters else pd.DataFrame(columns=["pivot","key","size","domains"])
    cl.to_csv("data/campaigns.csv", index=False)
    print(f"{len(cl)} campaign clusters -> data/campaigns.csv")
    if len(cl):
        print(cl.head(10).to_string(index=False)[:1200])

    # ---- forward prediction from naming templates ---------------
    templates = set()
    for d, v in facts.items():
        t = template_of(d, v["brand"])
        if t and t != d:
            templates.add(t)
    print(f"\n{len(templates)} naming templates extracted")

    candidates = {t.format(brand=b) for t in templates for b in TERMS}
    candidates -= set(facts)
    print(f"{len(candidates)} predicted domains to probe")

    hits = []
    with ThreadPoolExecutor(max_workers=50) as pool:
        futs = {pool.submit(ip_of, c): c for c in candidates}
        for f in as_completed(futs):
            ip = f.result()
            if ip:
                hits.append({"domain": futs[f], "ip": ip})

    pr = pd.DataFrame(hits)
    pr.to_csv("data/predicted.csv", index=False)
    print(f"\n{len(pr)} predicted domains are REGISTERED -> data/predicted.csv")
    if len(pr):
        print(pr.head(20).to_string(index=False))