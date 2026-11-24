# API contract

Base: `http://127.0.0.1:8000` — CORS is open, so static HTML works from disk.
**This shape does not change.** Build against it.

## POST /check
```json
{ "url": "https://adcb-secure.xyz/login", "deep": true }
```
`deep: false` skips the live page fetch, TLS handshake and cloaking probe.

```json
{
  "url": "...", "host": "...", "reg_domain": "...",
  "status": "CONFIRMED | REPORTED | SUSPICIOUS | NO_MATCH | UNKNOWN",
  "verdict": "malicious | suspicious | clean",
  "score": 87,
  "cached": false,
  "advisory": "Automated risk assessments are advisory and are not proof of fraud.",
  "reasons": [
    { "code": "rule", "direction": "risk|safe|neutral", "text": "readable sentence" }
  ],
  "enrichment": { "age_bucket": 0, "tls_free_ca": 1, "cloaked": 0, "...": "..." },
  "checked_at": "2026-11-24T19:30:00+00:00"
}
```

### status, and why it matters
| status | meaning |
|---|---|
| `CONFIRMED` | A human reviewer verified it. The only status we present as certain. |
| `REPORTED` | Our discovery layer or a user flagged it. **Unverified.** |
| `SUSPICIOUS` | Scored above the escalation threshold this request. |
| `NO_MATCH` | Nothing known. **Not the same as safe** — say so in the UI. |
| `UNKNOWN` | Lookup unavailable. |

Never render `NO_MATCH` as "Safe". Use the `reasons` text, which already says
*"No known reports found for this address. This does not guarantee it is safe."*

## POST /check-number
```json
{ "number": "+971551234567", "brand_context": "ADCB" }
```
Same response shape.

## Dashboard reads
| Endpoint | Returns |
|---|---|
| `GET /stats` | headline counts for the console |
| `GET /detections?limit&brand&min_score&source` | the detection table |
| `GET /campaigns` | infrastructure clusters + predicted domains |
| `GET /confirmed` | human-verified domains only |
| `GET /reviews` | the audit trail |

## POST /review
The **only** path from `REPORTED` into `CONFIRMED`.
```json
{ "domain": "adcb-secure.xyz", "decision": "confirm", "reviewer": "investigator" }
```
Writes to `data/confirmed.csv` and appends to `data/reviews.csv`.

## Rules anything consuming this must follow
1. Discovery output is **never** presented as confirmed.
2. Absence of a record is **never** presented as safe.
3. `reasons[].text` is written for a human — render it as-is, don't replace it
   with codes or raw scores. That list is what the explainability criterion scores.
