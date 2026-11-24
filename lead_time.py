"""
How far ahead of the public feeds are we?
Re-checks every CT discovery against the current public feeds.
  out: data/lead_time.csv
"""
import pathlib
from datetime import datetime, timezone

import httpx, pandas as pd, tldextract

UA = {"User-Agent": "Mozilla/5.0 (compatible; scam-detect-research/0.1)"}


def reg_of(host):
    e = tldextract.extract(host)
    return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else host


def public_now():
    out = set()
    for url in ("https://openphish.com/feed.txt", "https://phishunt.io/feed.txt"):
        try:
            r = httpx.get(url, headers=UA, timeout=30)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    h = line.split("//")[-1].split("/")[0].strip().lower()
                    if h:
                        out.add(reg_of(h))
        except Exception as e:
            print(f"  {url} failed: {e.__class__.__name__}")
    for name in ("openphish.txt", "phishdb.txt"):
        p = pathlib.Path("data/raw") / name
        if p.exists():
            for line in p.read_text("utf-8", errors="ignore").splitlines():
                h = line.split("//")[-1].split("/")[0].strip().lower()
                if h:
                    out.add(reg_of(h))
    return out


if __name__ == "__main__":
    df = pd.read_csv("data/ct_hits.csv").drop_duplicates("domain")
    pub = public_now()
    print(f"{len(pub)} domains known to public feeds right now\n")

    now = datetime.now(timezone.utc)
    rows = []
    for r in df.itertuples():
        try:
            seen = datetime.fromisoformat(str(r.first_seen_by_us))
        except Exception:
            continue
        was_public = str(getattr(r, "already_in_public_feed", 0)) == "1"
        is_pub_now = r.domain in pub
        rows.append({
            "domain": r.domain, "brand": r.brand,
            "was_public_when_found": int(was_public),
            "is_public_now": int(is_pub_now),
            "hours_ahead": round((now - seen).total_seconds() / 3600, 1)
                           if (is_pub_now and not was_public) else None,
            "still_unknown": int(not is_pub_now and not was_public),
        })

    out = pd.DataFrame(rows)
    out.to_csv("data/lead_time.csv", index=False)

    total = len(out)
    ahead = out[out.hours_ahead.notna()]
    never = int(out.still_unknown.sum())
    was_known = int(out.was_public_when_found.sum())

    print("=" * 58)
    print(f"  CT discoveries                : {total}")
    print(f"  Already public when we found  : {was_known}")
    print(f"  Found FIRST, public later     : {len(ahead)}")
    print(f"  Found FIRST, still unknown    : {never}")
    if len(ahead):
        print(f"  Median lead time              : {ahead.hours_ahead.median():.1f} h")
    print("=" * 58)
    print(f"\n{total - was_known} of {total} were unknown to every public feed "
          f"at the moment we detected them.")
