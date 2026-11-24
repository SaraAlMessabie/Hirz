import csv, random, pathlib
from urllib.parse import urlparse
import tldextract

RAW = pathlib.Path("data/raw"); random.seed(42)

def host_of(s):
    s = s.strip()
    if not s or s.startswith("#") or s.startswith("<"): return None
    h = urlparse(s).hostname if "://" in s else s.split("/")[0]
    if not h or "." not in h: return None
    return h.lower().strip(".")

phish = set()
for name in ["openphish.txt", "phishdb.txt"]:
    p = RAW/name
    if p.exists():
        for line in p.read_text("utf-8", errors="ignore").splitlines():
            h = host_of(line)
            if h: phish.add(h)

p = RAW/"phishunt.csv"
if p.exists():
    for row in csv.DictReader(p.read_text("utf-8", errors="ignore").splitlines()):
        h = host_of(row.get("url") or row.get("domain") or "")
        if h: phish.add(h)
print(f"phishing hosts: {len(phish)}")

phish_regs = set()
for h in phish:
    e = tldextract.extract(h)
    if e.domain and e.suffix: phish_regs.add(f"{e.domain}.{e.suffix}")

ranked = []
for line in (RAW/"tranco.csv").read_text("utf-8", errors="ignore").splitlines():
    a = line.split(",")
    if len(a) == 2 and a[0].isdigit(): ranked.append((int(a[0]), a[1].strip().lower()))

BANDS = [(1,1_000), (1_000,10_000), (10_000,100_000), (100_000,1_000_000)]
per = max(1, len(phish)//len(BANDS))
benign = []
for lo, hi in BANDS:
    pool = [d for r,d in ranked if lo <= r < hi and d not in phish_regs]
    benign += random.sample(pool, min(per, len(pool)))
print(f"benign hosts:   {len(benign)} ({per} per band)")

with open("data/dataset.csv","w",newline="",encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["host","label"])
    for h in sorted(phish):  w.writerow([h,1])
    for h in sorted(benign): w.writerow([h,0])
print("wrote data/dataset.csv")