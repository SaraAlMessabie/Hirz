import pathlib

RAW = pathlib.Path("data/raw")

for f in sorted(RAW.iterdir()):
    lines = len(f.read_text("utf-8", errors="ignore").splitlines())
    print(f"{f.name:25} {f.stat().st_size//1024:>8} KB   {lines:>8} lines")