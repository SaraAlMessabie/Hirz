"""
Evidence report service for the web check page (Task 4 + 5).

  python -m uvicorn evidence_server:app --port 8001      (api.py must be running on :8000)

  POST /evidence  {"url": "https://..."}
       -> the bilingual PDF (page 1 English, page 2 Arabic) as a download.
          Also saved to evidence/<id>.json and evidence/<id>.pdf.
  GET  /health    -> {"ok": true}

The service calls /check itself rather than trusting a result sent by the
browser, so the report always reflects what the checker actually returned.
Env: HIRZ_API (default http://127.0.0.1:8000)
"""
import os

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

import evidence

API = os.environ.get("HIRZ_API", "http://127.0.0.1:8000").rstrip("/")

app = FastAPI(title="hirz-evidence")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
                   expose_headers=["Content-Disposition", "X-Evidence-Id", "X-Bundle-SHA256"])


class UrlIn(BaseModel):
    url: str


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/evidence")
def make_evidence(body: UrlIn):
    try:
        r = httpx.post(API + "/check", json={"url": body.url, "deep": True}, timeout=60)
        r.raise_for_status()
    except Exception:
        raise HTTPException(502, f"Could not reach the checker API at {API}")
    b = evidence.build(r.json())
    _, pdf_path = evidence.save(b)
    with open(pdf_path, "rb") as f:
        data = f.read()
    eid = b["evidence_id"]
    return Response(data, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="hirz-evidence-{eid}.pdf"',
        "X-Evidence-Id": eid,
        "X-Bundle-SHA256": b["bundle_sha256"],
    })
