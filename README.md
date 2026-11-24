# Scam link and helpline detection

Finds impersonation domains and fake helpline numbers **before the first victim
reports them**, and turns each one into evidence a registrar or investigator
can act on.

## Run it

```bash
python -m venv .venv && .venv/Scripts/Activate.ps1      # Windows
pip install lightgbm shap fastapi uvicorn httpx beautifulsoup4 lxml pandas \
            tldextract dnspython phonenumbers imagehash pillow dnstwist \
            fpdf2 scikit-learn mmh3

python features.py          # build data/features.csv
python train.py             # -> data/model.pkl
uvicorn api:app --reload --port 8000
```

Then open `clients/dashboard.html` in a browser. Interactive API docs at `/docs`.

## How it works

| Tier | Does | Speed |
|---|---|---|
| 0 | Confirmed / reported lookup | instant |
| 1 | Lexical + domain features, LightGBM (0.875 acc / 0.931 AUC) | ~50 ms |
| 2 | RDAP age, TLS certificate, page forms, hotlinks, cloaking probe | 5–10 s |
| 3 | LLM adjudication, ambiguous cases only, via Ollama | 3–8 s |

Tier 3 never clears something a hard rule flagged, and the system runs
unchanged if Ollama is not available.

## Discovery — finding scams nobody reported

| Script | Finds |
|---|---|
| `ct_watch.py` | Certificate Transparency: impersonation domains minutes after issuance |
| `hunt_lookalikes.py` | Permutation sweep across protected brands |
| `triage_lookalikes.py` | Filters the sweep by registration age and verdict |
| `favicon_pivot.py` | Kit clusters by favicon hash — brand-independent |
| `campaign_clusters.py` | Registration-time, nameserver and ASN clustering |
| `pivot.py` | Naming templates → predicted future domains |
| `lead_time.py` | How far ahead of the public feeds we are |

## Data discipline

- **`data/confirmed.csv`** — human-verified only. The sole source of `CONFIRMED`.
- **`data/blocklist.csv`, `ct_hits.csv`, `lookalikes_triaged.csv`** — unverified
  discovery output. Served as `REPORTED`, never as confirmed.
- **`data/reviews.csv`** — audit trail of every confirm/reject decision.

Discovery never auto-promotes into confirmed. A human clicks Confirm in the
console, or it stays reported. Predicted domains go to a watchlist and are never
used as training labels.

## Not built here

`evidence.py` (evidence package + PDF), `clients/check.html` (citizen view),
listings/NAP scanning, and the brand reference CSVs — see the teammate brief.

## Known limitations

- crt.sh rate-limits aggressively; the watcher retries and degrades gracefully.
- Permutation hits on short brand names (`adcb`, `dhl`) collide with real
  businesses. Triage by registration age before trusting them.
- Campaign clustering by IP finds little behind Cloudflare — use
  `campaign_clusters.py` instead.
- Nothing here is a police system. The console is labelled a prototype.
