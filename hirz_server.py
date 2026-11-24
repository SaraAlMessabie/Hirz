"""
Hirz app server: one address for the whole demo.

  python -m uvicorn api:app --port 8000                          (Sara's checker API)
  python -m uvicorn hirz_server:app --host 0.0.0.0 --port 8001   (this file)
  then open  http://localhost:8001   or, on a phone,  http://<laptop-ip>:8001

Serves clients/index.html and these endpoints (the app calls them):
  GET  /api/health                 is the checker API reachable?
  GET  /api/brands                 brands from data/brands.csv (for the dropdowns)
  POST /api/check                  {"url"}                    -> proxied to api.py /check
  POST /api/check-number           {"number","brand_context"} -> proxied to api.py /check-number
  POST /api/listing                {"brand","name","address","phone","website","review_count"}
                                   -> one listing cross-checked (listing_scan.py)
  GET  /api/listings[?refresh=1]   the fixture listings, from data/listing_hits.csv
                                   (rescanned when missing or refresh=1)
  POST /api/evidence               {"url"} -> bilingual evidence PDF (evidence.py)
  POST /api/scan-message           {"text","lang"} -> SMS/WhatsApp scan (links, numbers, emails)
  POST /api/report                 a citizen files a report -> reference number
  GET  /api/reports[?status=]      the investigator queue
  POST /api/report-status          investigator moves a report through the queue
  plus /api/stats, /api/detections, /api/campaigns, /api/confirmed, /api/official,
       /api/review, /api/reviews   (allowlisted passthrough to api.py)

The investigator console is served by api.py on port 8000, not by this file.

Env: HIRZ_API (default http://127.0.0.1:8000), BRAVE_API_KEY, NOMINATIM_EMAIL (optional)
"""
import csv, os, pathlib

import httpx
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import evidence
import listing_scan

ROOT = pathlib.Path(__file__).resolve().parent
CLIENTS = ROOT / "clients"
API = os.environ.get("HIRZ_API", "http://127.0.0.1:8000").rstrip("/")

app = FastAPI(title="hirz")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
                   expose_headers=["Content-Disposition", "X-Evidence-Id", "X-Bundle-SHA256"])


class UrlIn(BaseModel):
    url: str


class NumIn(BaseModel):
    number: str
    brand_context: str | None = None


class ListingIn(BaseModel):
    brand: str = ""
    name: str = ""
    address: str = ""
    phone: str = ""
    website: str = ""
    review_count: int | None = None


def _proxy(path, payload):
    try:
        r = httpx.post(API + path, json=payload, timeout=60)
        r.raise_for_status()
        return r.json()
    except Exception:
        raise HTTPException(502, f"Could not reach the checker API at {API}. Start it with: "
                                 "python -m uvicorn api:app --port 8000")


def _proxy_get(path, params=None):
    try:
        r = httpx.get(API + path, params=params or {}, timeout=60)
        r.raise_for_status()
        return r.json()
    except Exception:
        raise HTTPException(502, f"Could not reach the checker API at {API}. Start it with: "
                                 "python -m uvicorn api:app --port 8000")


@app.get("/api/health")
def health():
    try:
        ok = httpx.get(API + "/docs", timeout=5).status_code == 200
    except Exception:
        ok = False
    return {"server": True, "checker_api": ok, "api": API}


@app.get("/api/brands")
def brands():
    rows = csv.DictReader(open(ROOT / "data" / "brands.csv", encoding="utf-8"))
    return [{"brand": r["brand"], "display_name": r["display_name"]} for r in rows]


@app.post("/api/check")
def check(body: UrlIn):
    return _proxy("/check", {"url": body.url, "deep": True})


@app.post("/api/check-number")
def check_number(body: NumIn):
    return _proxy("/check-number", {"number": body.number, "brand_context": body.brand_context})


@app.post("/api/listing")
def listing(body: ListingIn):
    _proxy("/check-number", {"number": "+97126962222"})          # fail fast if the API is down
    b, br = listing_scan.load_refs()
    row = listing_scan.scan_one(body.model_dump(), API, b, br,
                                os.environ.get("BRAVE_API_KEY", ""), os.environ.get("NOMINATIM_EMAIL", ""))
    row["reasons"] = row["reasons"].split(" | ")
    return row


@app.get("/api/listings")
def listings(refresh: int = 0):
    out = listing_scan.OUT
    if refresh or not out.exists():
        _proxy("/check-number", {"number": "+97126962222"})
        rows = listing_scan.scan(API, "", os.environ.get("BRAVE_API_KEY", ""), os.environ.get("NOMINATIM_EMAIL", ""))
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader(); w.writerows(rows)
    rows = list(csv.DictReader(open(out, encoding="utf-8")))
    for r in rows:
        r["reasons"] = r["reasons"].split(" | ")
    return rows


@app.post("/api/evidence")
def make_evidence(body: UrlIn):
    """Runs /check itself rather than trusting a result sent by the browser."""
    b = evidence.build(_proxy("/check", {"url": body.url, "deep": True}))
    _, pdf_path = evidence.save(b)
    data = pathlib.Path(pdf_path).read_bytes()
    eid = b["evidence_id"]
    return Response(data, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="hirz-evidence-{eid}.pdf"',
        "X-Evidence-Id": eid, "X-Bundle-SHA256": b["bundle_sha256"]})


# Everything else api.py serves, reachable through this one address.
# Declared after the routes above, so those keep priority.
PASS_POST = {"report", "report-status", "scan-message", "review", "official"}
PASS_GET = {"reports", "reviews", "stats", "detections", "campaigns", "confirmed", "official"}


@app.post("/api/{path:path}")
def pass_post(path: str, body: dict = Body(default={})):
    if path not in PASS_POST:
        raise HTTPException(404, f"No such endpoint: /api/{path}")
    return _proxy("/" + path, body)


@app.get("/api/{path:path}")
def pass_get(path: str, request: Request):
    if path not in PASS_GET:
        raise HTTPException(404, f"No such endpoint: /api/{path}")
    return _proxy_get("/" + path, dict(request.query_params))


@app.get("/")
def index():
    return FileResponse(CLIENTS / "index.html")


app.mount("/", StaticFiles(directory=CLIENTS), name="clients")
