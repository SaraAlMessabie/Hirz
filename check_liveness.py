# check_liveness.py
import random, sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import httpx, tldextract, dns.resolver

UA = {"User-Agent": "Mozilla/5.0 (compatible; scam-detect-research/0.1)"}
FEEDS = ["https://openphish.com/feed.txt", "https://phishunt.io/feed.txt"]

def reg_domain(s):
    s = s.strip()
    if not s or s.startswith("#") or s.startswith("<"):
        return None
    host = urlparse(s).hostname if "://" in s else s.split("/")[0]
    if not host:
        return None
    e = tldextract.extract(host)
    return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else None

def get_lines(path=None):
    if path:
        text = open(path, encoding="utf-8", errors="ignore").read()
        print(f"read {path}: {len(text)} chars")
        return text.splitlines()
    for url in FEEDS:
        try:
            r = httpx.get(url, timeout=60, headers=UA, follow_redirects=True)
            print(f"{url} -> HTTP {r.status_code}, {len(r.text)} chars")
            if r.status_code == 200 and r.text.strip():
                print("  first line:", r.text.splitlines()[0][:120])
                return r.text.splitlines()
        except Exception as e:
            print(f"{url} -> FAILED: {e}")
    return []

_res = dns.resolver.Resolver(); _res.timeout = _res.lifetime = 3
def resolves(d):
    try:
        _res.resolve(d, "A"); return True
    except Exception:
        return False

if __name__ == "__main__":
    lines = get_lines(sys.argv[1] if len(sys.argv) > 1 else None)
    print(f"{len(lines)} raw lines")

    domains = sorted({d for d in map(reg_domain, lines) if d})
    print(f"{len(domains)} unique domains")

    if not domains:
        print("\nNO DOMAINS PARSED. First 5 raw lines were:")
        for l in lines[:5]:
            print("   ", repr(l[:120]))
        sys.exit(1)

    sample = random.sample(domains, min(300, len(domains)))
    with ThreadPoolExecutor(max_workers=50) as pool:
        alive = sum(pool.map(resolves, sample))
    print(f"\n{alive}/{len(sample)} resolve -> {100*alive/len(sample):.0f}% live")