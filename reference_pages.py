"""
Fingerprint the official pages scammers clone.
  python reference_pages.py  ->  data/references.json
"""
import hashlib, json, pathlib, re

import httpx
from bs4 import BeautifulSoup

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"}

REFERENCES = {
    "adcb":         ["https://www.adcb.com/en/personal/"],
    "emiratesnbd":  ["https://www.emiratesnbd.com/en/"],
    "aramex":       ["https://www.aramex.com/ae/en/track/shipments"],
    "emiratespost": ["https://www.emiratespost.ae/en"],
    "uaepass":      ["https://www.uaepass.ae/"],
    "dhl":          ["https://www.dhl.com/ae-en/home/tracking.html"],
}


def fingerprint(html, url=""):
    soup = BeautifulSoup(html, "lxml")
    for t in soup(["script", "style", "noscript"]):
        t.decompose()

    tags = [t.name for t in soup.find_all(True)]
    shingles = {"|".join(tags[i:i + 4]) for i in range(max(0, len(tags) - 3))}

    classes = set()
    for t in soup.find_all(True):
        for c in (t.get("class") or []):
            if len(c) > 3:
                classes.add(c.lower())

    fields = {(i.get("name") or i.get("id") or "").lower()
              for i in soup.find_all("input") if (i.get("name") or i.get("id"))}

    assets = set()
    for t in soup.find_all(["img", "link"]):
        src = t.get("src") or t.get("href") or ""
        base = re.sub(r"\?.*$", "", src).rsplit("/", 1)[-1].lower()
        if base and "." in base:
            assets.add(base)

    text = re.sub(r"\s+", " ", soup.get_text(" ")).lower()
    words = {w for w in re.findall(r"[a-z]{4,}", text)}

    return {"url": url, "tag_count": len(tags),
            "shingles": sorted(shingles), "classes": sorted(classes),
            "fields": sorted(fields), "assets": sorted(assets),
            "words": sorted(words)[:800],
            "dom_hash": hashlib.sha256("|".join(tags).encode()).hexdigest()[:16]}


def jaccard(a, b):
    a, b = set(a), set(b)
    return len(a & b) / len(a | b) if (a or b) else 0.0


def similarity(sus, ref):
    s = {"dom":     jaccard(sus["shingles"], ref["shingles"]),
         "classes": jaccard(sus["classes"],  ref["classes"]),
         "fields":  jaccard(sus["fields"],   ref["fields"]),
         "assets":  jaccard(sus["assets"],   ref["assets"]),
         "words":   jaccard(sus["words"],    ref["words"])}
    s["overall"] = round(0.35 * s["dom"] + 0.25 * s["classes"] +
                         0.15 * s["fields"] + 0.15 * s["assets"] +
                         0.10 * s["words"], 3)
    return s


if __name__ == "__main__":
    out = {}
    for brand, urls in REFERENCES.items():
        for u in urls:
            try:
                r = httpx.get(u, headers=UA, timeout=20, follow_redirects=True)
                fp = fingerprint(r.text, str(r.url))
                out.setdefault(brand, []).append(fp)
                print(f"{brand:14} {fp['tag_count']:>5} tags  "
                      f"{len(fp['classes']):>4} classes  {len(fp['assets']):>3} assets")
            except Exception as e:
                print(f"{brand:14} FAILED {e.__class__.__name__}")

    pathlib.Path("data").mkdir(exist_ok=True)
    pathlib.Path("data/references.json").write_text(json.dumps(out), "utf-8")
    print(f"\nwrote data/references.json  ({sum(len(v) for v in out.values())} pages)")
