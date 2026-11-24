"""
Tier 3 - LLM adjudicator for the ambiguous middle band.
Fails silently: if Ollama isn't running, returns {} and nothing changes.
"""
import json
import httpx

OLLAMA = "http://localhost:11434/api/generate"
MODEL = "qwen3:4b"

PROMPT = """You are analysing a webpage for brand impersonation and fraud.
Reply with JSON only, no prose:
{"impersonated_brand": string or null,
 "intent": "credential_theft" | "payment_fraud" | "legitimate" | "unclear",
 "confidence": 0-100,
 "language": "en" | "ar" | "mixed" | "other",
 "evidence": [up to 3 short factual observations]}

Evidence packet:
"""

def evidence_packet(host, row, tls, page):
    return {
        "domain": host,
        "registered_days_ago_bucket": row.get("age_bucket"),
        "tld": host.rsplit(".", 1)[-1],
        "certificate": {
            "issuer_free_ca": tls.get("tls_free_ca"),
            "verified_organisation": tls.get("tls_org") or None,
            "age_days": tls.get("tls_age_days"),
        },
        "page": {
            "title": (page.get("title") or "")[:120],
            "has_password_field": page.get("has_password"),
            "has_card_field": page.get("has_card_field"),
            "form_posts_offsite": page.get("form_cross_domain"),
            "loads_assets_from": (page.get("hotlinked_domains") or [])[:5],
            "redirects": page.get("redirect_count"),
        },
        "visible_text": (page.get("text") or "")[:1500],
    }

def llm_check(packet, timeout=20):
    try:
        r = httpx.post(OLLAMA, timeout=timeout,
                       json={"model": MODEL, "stream": False, "format": "json",
                             "prompt": PROMPT + json.dumps(packet, ensure_ascii=False)})
        if r.status_code != 200:
            return {}
        return json.loads(r.json().get("response", "{}"))
    except Exception:
        return {}