# Putting Hirz online

Two ways. The tunnel is for the live demo; Render is for a link that outlives
the laptop. Doing both is sensible.

---

## 1. Tunnel — the demo path

Serves whatever is running on your laptop right now, over a public HTTPS URL.
No cold start, full CPU, nothing gets wiped, and Ollama still works. Changes go
live the moment you restart uvicorn.

Install once:

```powershell
winget install --id Cloudflare.cloudflared
```

Then, with both servers already running, open two more terminals:

```powershell
cloudflared tunnel --url http://localhost:8001     # citizen app
```

```powershell
cloudflared tunnel --url http://localhost:8010     # investigator console
```

Each prints a `https://<random-words>.trycloudflare.com` URL. Share those.

The URLs change every time you restart the tunnel, so start them once and leave
them up. Judges can open them on their own phones.

### If only one tunnel

Tunnel 8001 and reach the console through the app's tunnel by passing the API
address explicitly:

```
https://<your-tunnel>.trycloudflare.com/dashboard.html?api=https://<api-tunnel>.trycloudflare.com
```

---

## 2. Render — the permanent link

`render.yaml` defines two free services. Free instances spin down after 15
minutes idle and spun-down instances consume no instance hours, so two fit
inside the 750 hours a month.

1. Push to GitHub (done).
2. Render dashboard -> New -> Blueprint -> pick this repo. It reads
   `render.yaml`.
3. It will ask for `HIRZ_API`. First deploy `hirz-api`, copy its URL
   (`https://hirz-api.onrender.com`), then set that as `HIRZ_API` on `hirz-app`.
   `BRAVE_API_KEY` and `NOMINATIM_EMAIL` are optional; leave blank if unused.

**Which URL is which**

| Open this | For |
|---|---|
| `https://hirz-app.onrender.com` | the citizen app |
| `https://hirz-api.onrender.com` | the investigator console |

Use the **api** URL for the console. `api.py` serves `dashboard.html` at `/`, so
the console talks to its own origin and finds every endpoint. Opening the
console from the app service instead gives you a page whose calls 404, because
that service only answers under `/api`.

### What to expect on the free tier

- **Cold start.** After 15 minutes idle the first request waits 30-60 seconds.
  Open both URLs a minute before anyone else does.
- **The filesystem is wiped on every deploy and every spin-down.** The seed rows
  in `data/confirmed.csv`, `data/reports.csv` and `data/reviews.csv` come back
  because they are in git. Anything added while the service is up does not.
- **512MB RAM, 0.1 CPU.** Deep checks are slower than on your laptop.
- **No Ollama.** Tier 3 is skipped; the other three tiers are unaffected.
- **Stop pushing about an hour before you present.** A build takes a few minutes
  and the service cold-starts afterwards.

### Pin lightgbm to the version that trained the model

```powershell
python -c "import lightgbm, sklearn, joblib; print(lightgbm.__version__, sklearn.__version__, joblib.__version__)"
```

Put that lightgbm version in `requirements.txt` as `lightgbm==<version>` before
deploying. A major-version gap can refuse to unpickle `data/model.pkl`.

### Secrets

Never commit a key. Render env vars are set in the dashboard; `render.yaml`
marks them `sync: false` so the file never carries a value.
