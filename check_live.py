import httpx, pandas as pd

df = pd.read_csv("data/lookalikes_triaged.csv")
live = df[(df.age_bucket >= 0) & (df.age_bucket <= 3)]

rows = []
for d in live.domain:
    try:
        v = httpx.post("http://127.0.0.1:8000/check",
                       json={"url": d, "deep": True}, timeout=30).json()
    except Exception:
        continue
    e = v.get("enrichment", {})
    rows.append({"domain": d, "verdict": v.get("verdict"), "score": v.get("score"),
                 "status": e.get("status"), "title": e.get("title", "")[:50],
                 "has_password": e.get("has_password"),
                 "cross_domain": e.get("form_cross_domain"),
                 "top_reason": (v.get("reasons") or [{}])[0].get("text", "")[:60]})

out = pd.DataFrame(rows)
out.to_csv("data/lookalikes_live.csv", index=False)
print(out[out.status.notna()].to_string(index=False))