import io, zipfile, pathlib, httpx

DATA = pathlib.Path("data"); (DATA / "raw").mkdir(parents=True, exist_ok=True)
UA = {"User-Agent": "Mozilla/5.0 (compatible; scam-detect-research/0.1)"}

def save(name, url):
    dst = DATA / "raw" / name
    if dst.exists():
        print(f"skip {name} ({dst.stat().st_size//1024} KB)"); return
    print(f"get  {name} ...", end=" ", flush=True)
    try:
        r = httpx.get(url, timeout=120, headers=UA, follow_redirects=True)
        r.raise_for_status()
        dst.write_bytes(r.content)
        print(f"{len(r.content)//1024} KB")
    except Exception as e:
        print(f"FAILED ({e.__class__.__name__}) - skipping")

save("openphish.txt", "https://openphish.com/feed.txt")
save("phishunt.csv",  "https://phishunt.io/feed.csv")

dst = DATA / "raw" / "tranco.csv"
if dst.exists():
    print(f"skip tranco.csv ({dst.stat().st_size//1024} KB)")
else:
    print("get  tranco ...", end=" ", flush=True)
    try:
        r = httpx.get("https://tranco-list.eu/top-1m.csv.zip",
                      timeout=300, headers=UA, follow_redirects=True)
        r.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            dst.write_bytes(z.read(z.namelist()[0]))
        print(f"{dst.stat().st_size//1024} KB")
    except Exception as e:
        print(f"FAILED ({e.__class__.__name__})")

print("\n--- data/raw ---")
for f in sorted((DATA/"raw").iterdir()):
    print(f"{f.name:20} {f.stat().st_size//1024:>8} KB")