"""
Evidence package (Task 4).

  build(check_response) -> dict      bundle with a chain-of-custody hash
  verify(bundle) -> bool             recompute bundle_sha256

  python evidence.py <url>           calls POST /check, writes evidence/<id>.json + .pdf
  python evidence.py --verify evidence/<id>.json

Options:  --api http://127.0.0.1:8000   where api.py is running
Env:      URLSCAN_API_KEY               optional; adds a screenshot via urlscan.io

The page is fetched once with a plain HTTP GET (no JavaScript is run).
If something can't be collected, the field says so — nothing is invented.
"""
import argparse, hashlib, json, os, pathlib, socket, ssl, sys, time, uuid
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import httpx

from tier2 import bootstrap, reg_of

OUT = pathlib.Path("evidence")
RDAP_CACHE = pathlib.Path("cache/rdap")
UA = {"User-Agent": "Mozilla/5.0 (compatible; hirz-evidence/0.1)"}
CLOUDFLARE_ASN = "13335"


# ---------------------------------------------------------------- helpers
def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical(obj) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def seal(bundle: dict) -> str:
    body = {k: v for k, v in bundle.items() if k != "bundle_sha256"}
    return hashlib.sha256(canonical(body)).hexdigest()


def verify(bundle: dict) -> bool:
    return bundle.get("bundle_sha256") == seal(bundle)


def _days_since(iso):
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def _vcard(entity, field):
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == field:
            val = item[3]
            if isinstance(val, list):
                val = " ".join(str(v) for v in val if v)
            return str(val).replace("mailto:", "").replace("tel:", "").strip()
    return ""


def _abuse(entities):
    """Find an abuse contact anywhere in an RDAP entity tree."""
    for e in entities or []:
        if "abuse" in (e.get("roles") or []):
            email, phone = _vcard(e, "email"), _vcard(e, "tel")
            if email or phone:
                return {"email": email, "phone": phone}
        found = _abuse(e.get("entities"))
        if found:
            return found
    return {}


# ---------------------------------------------------------------- collectors
def fetch_page(url):
    """One plain GET. Returns html hash, redirect chain, final URL."""
    if "://" not in url:
        url = "https://" + url
    try:
        r = httpx.get(url, timeout=10, follow_redirects=True, headers=UA)
    except Exception as e:
        return {"error": f"Page could not be fetched: {type(e).__name__}"}
    chain = [{"url": str(h.url), "status": h.status_code} for h in r.history]
    chain.append({"url": str(r.url), "status": r.status_code})
    return {"html_sha256": hashlib.sha256(r.content).hexdigest(),
            "html_bytes": len(r.content),
            "final_url": str(r.url),
            "redirect_chain": chain}


def registration(domain):
    """RDAP: registrar, abuse contact, dates, nameservers. Uses tier2's cache."""
    d, source = None, ""
    f = RDAP_CACHE / f"{domain}.json"
    if f.exists():
        try:
            d, source = json.loads(f.read_text("utf-8")), "rdap (cached)"
        except Exception:
            d = None
    if d is None:
        base = bootstrap().get(domain.rsplit(".", 1)[-1])
        if not base:
            return {"found": False, "note": "No RDAP server for this TLD"}
        try:
            r = httpx.get(f"{base}/domain/{domain}", timeout=10, follow_redirects=True,
                          headers={**UA, "Accept": "application/rdap+json"})
            if r.status_code != 200:
                return {"found": False, "note": f"RDAP returned HTTP {r.status_code}"}
            d, source = r.json(), f"{base}/domain/{domain}"
        except Exception as e:
            return {"found": False, "note": f"RDAP lookup failed: {type(e).__name__}"}
    if not isinstance(d, dict) or "events" not in d:
        return {"found": False, "note": "No RDAP record"}

    ev = {(e.get("eventAction") or "").lower(): e.get("eventDate") for e in d.get("events") or []}
    registrar = next((e for e in d.get("entities") or [] if "registrar" in (e.get("roles") or [])), {})
    iana = next((p.get("identifier") for p in registrar.get("publicIds") or []
                 if "iana" in (p.get("type") or "").lower()), "")
    return {
        "found": True,
        "source": source,
        "registrar": _vcard(registrar, "fn"),
        "registrar_iana_id": iana,
        "registrar_abuse": _abuse([registrar]) or _abuse(d.get("entities")),
        "created": ev.get("registration"),
        "expires": ev.get("expiration"),
        "age_days": _days_since(ev.get("registration")),
        "nameservers": [n.get("ldhName", "").lower() for n in d.get("nameservers") or []],
        "status": d.get("status") or [],
    }


def certificate(host):
    """Live TLS certificate: issuer, validity, organisation."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                c = ss.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return {"found": False, "note": f"Certificate failed verification: {e.verify_message}"}
    except Exception as e:
        return {"found": False, "note": f"No HTTPS certificate retrieved: {type(e).__name__}"}

    def name(part, key):
        return next((v for t in c.get(part, ()) for k, v in t if k == key), "")

    sans = [v for k, v in c.get("subjectAltName", ()) if k == "DNS"]
    return {"found": True,
            "issuer": name("issuer", "organizationName") or name("issuer", "commonName"),
            "issuer_cn": name("issuer", "commonName"),
            "subject_cn": name("subject", "commonName"),
            "organisation": name("subject", "organizationName") or "(none — domain-validated only)",
            "valid_from": c.get("notBefore"),
            "valid_to": c.get("notAfter"),
            "san_count": len(sans),
            "san_sample": sans[:5]}


def _txt(name):
    import dns.resolver
    return [b"".join(r.strings).decode() for r in dns.resolver.resolve(name, "TXT", lifetime=5)]


def hosting(host):
    """IP (dnspython), ASN (Team Cymru DNS), network abuse contact (RDAP)."""
    out = {"ip": "", "asn": "", "as_name": "", "abuse": {}}
    try:
        import dns.resolver
        out["ip"] = dns.resolver.resolve(host, "A", lifetime=5)[0].to_text()
    except Exception:
        try:
            out["ip"] = socket.gethostbyname(host)
        except Exception:
            out["note"] = "Host does not resolve"
            return out
    try:
        rev = ".".join(reversed(out["ip"].split(".")))
        asn = _txt(f"{rev}.origin.asn.cymru.com")[0].split("|")[0].strip().split()[0]
        out["asn"] = asn
        out["as_name"] = _txt(f"AS{asn}.asn.cymru.com")[0].split("|")[-1].strip()
    except Exception:
        out["note"] = "ASN lookup failed"
    try:
        r = httpx.get(f"https://rdap.org/ip/{out['ip']}", timeout=10, follow_redirects=True,
                      headers={**UA, "Accept": "application/rdap+json"})
        if r.status_code == 200:
            out["abuse"] = _abuse(r.json().get("entities"))
    except Exception:
        pass
    return out


def screenshot(url, evidence_id):
    """urlscan.io if URLSCAN_API_KEY is set. Never fabricates an image."""
    key = os.environ.get("URLSCAN_API_KEY", "").strip()
    if not key:
        return None, "No screenshot: urlscan.io API key not configured (URLSCAN_API_KEY).", ""
    h = {"API-Key": key, "Content-Type": "application/json"}
    try:
        r = httpx.post("https://urlscan.io/api/v1/scan/", headers=h, timeout=15,
                       json={"url": url, "visibility": "unlisted"})
        if r.status_code != 200:
            return None, f"No screenshot: urlscan refused the scan (HTTP {r.status_code}).", ""
        scan = r.json()["uuid"]
        report = f"https://urlscan.io/result/{scan}/"
        for _ in range(12):                                # up to ~60 s
            time.sleep(5)
            if httpx.get(f"https://urlscan.io/api/v1/result/{scan}/", timeout=10).status_code == 200:
                break
        png = httpx.get(f"https://urlscan.io/screenshots/{scan}.png", timeout=20)
        if png.status_code != 200 or not png.content.startswith(b"\x89PNG"):
            return None, "No screenshot: urlscan finished but stored no image.", report
        OUT.mkdir(exist_ok=True)
        path = OUT / f"{evidence_id}.png"
        path.write_bytes(png.content)
        return str(path), "Rendered by urlscan.io (independent scanner).", report
    except Exception as e:
        return None, f"No screenshot: urlscan unavailable ({type(e).__name__}).", ""


def takedown(b):
    """Where to send it, most effective first. Not the certificate authority:
    CAs (e.g. Let's Encrypt, Google Trust Services) don't revoke for phishing."""
    reg, host = b.get("registration") or {}, b.get("hosting") or {}
    abuse = reg.get("registrar_abuse") or {}
    targets = [{
        "rank": 1, "target": "Registrar abuse contact",
        "why": "Suspending the domain takes down every URL on it at once.",
        "name": reg.get("registrar") or "Unknown registrar",
        "email": abuse.get("email", ""), "phone": abuse.get("phone", ""),
        "note": "" if abuse else "RDAP listed no abuse contact; use the registrar's website.",
    }]
    if host.get("asn") == CLOUDFLARE_ASN:
        targets.append({"rank": 2, "target": "Cloudflare (proxy in front of the real host)",
                        "why": "Cloudflare forwards abuse reports to the hosting provider behind it.",
                        "name": "Cloudflare, Inc.", "url": "https://abuse.cloudflare.com/"})
    else:
        hab = host.get("abuse") or {}
        targets.append({"rank": 2, "target": "Hosting provider",
                        "why": "Content removal from the server.",
                        "name": host.get("as_name") or "Unknown network",
                        "asn": host.get("asn", ""), "email": hab.get("email", ""),
                        "note": "" if hab else "No network abuse contact found."})
    targets.append({"rank": 3, "target": "Google Safe Browsing",
                    "why": "Warns every Chrome, Firefox and Safari user who opens the link.",
                    "url": "https://safebrowsing.google.com/safebrowsing/report_phish/?url="
                           + quote(b.get("url", ""), safe="")})
    targets.append({"rank": 4, "target": "Police case file",
                    "why": "Only for confirmed campaigns with UAE exposure.",
                    "applies": b.get("verdict") == "malicious",
                    "note": "Submit this PDF through official AD Police channels."})
    return targets


# ---------------------------------------------------------------- bundle
def build(check_response: dict, fetch: bool = True) -> dict:
    r = check_response
    url = r.get("url", "")
    host = (r.get("host") or urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    reg_domain = r.get("reg_domain") or reg_of(host)
    eid = "ev_" + uuid.uuid4().hex[:10]
    enrich = r.get("enrichment") or {}

    b = {"evidence_id": eid, "url": url, "host": host, "reg_domain": reg_domain,
         "verdict": r.get("verdict", "unknown"), "score": r.get("score"),
         "reasons": r.get("reasons") or [],
         "checked_at": r.get("checked_at"), "captured_at": now()}

    page = fetch_page(url) if fetch else {"error": "Page fetch skipped"}
    b["html_sha256"] = page.get("html_sha256")
    b["final_url"] = page.get("final_url")
    b["redirect_chain"] = enrich.get("redirect_chain") or page.get("redirect_chain") or []
    if "error" in page:
        b["page_note"] = page["error"]

    b["registration"] = registration(reg_domain)
    b["certificate"] = certificate(host) if fetch else {"found": False, "note": "Skipped"}
    b["hosting"] = hosting(host) if fetch else {"note": "Skipped"}

    shot, note, report = screenshot(url, eid) if fetch else (None, "No screenshot: skipped.", "")
    b["screenshot_path"], b["screenshot_note"], b["urlscan_report"] = shot, note, report
    if shot:
        b["screenshot_sha256"] = hashlib.sha256(pathlib.Path(shot).read_bytes()).hexdigest()

    b["takedown"] = takedown(b)
    b["bundle_sha256"] = seal(b)          # computed last, over everything above
    return b


# ---------------------------------------------------------------- PDF
VERDICT_TEXT = {
    "malicious":  ("MALICIOUS", (200, 30, 30),
                   "This link shows strong signs of a scam designed to steal personal or payment details."),
    "suspicious": ("SUSPICIOUS", (190, 120, 0),
                   "This link shows some warning signs and should be treated with caution."),
    "clean":      ("NO WARNINGS", (20, 130, 60),
                   "No warning signs were found. This does not guarantee the link is safe."),
    "unknown":    ("UNKNOWN", (100, 110, 125), "The link could not be assessed."),
}


def _t(s):
    """fpdf2 core fonts are Latin-1 only."""
    s = str(s if s is not None else "")
    for a, b in {"—": "-", "–": "-", "’": "'", "‘": "'", "“": '"', "”": '"', "…": "...", "✓": "+"}.items():
        s = s.replace(a, b)
    return s.encode("latin-1", "replace").decode("latin-1")


def render_pdf(b: dict, path):
    from fpdf import FPDF
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(False)
    pdf.set_margins(14, 12, 14)
    pdf.add_page()
    W = pdf.w - pdf.l_margin - pdf.r_margin
    L = pdf.l_margin

    def para(text, size=10, style="", h=5, color=(30, 30, 30)):
        pdf.set_font("Helvetica", style, size)
        pdf.set_text_color(*color)
        pdf.set_x(L)
        pdf.multi_cell(W, h, _t(text))
        pdf.set_x(L)

    word, rgb, meaning = VERDICT_TEXT.get(b.get("verdict"), VERDICT_TEXT["unknown"])

    # header band
    pdf.set_fill_color(*rgb)
    pdf.rect(0, 0, pdf.w, 34, "F")
    pdf.set_xy(L, 7)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 26)
    pdf.cell(W * 0.62, 12, _t(word))
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(W * 0.38, 12, _t(f"Risk score {b.get('score', '-')}/100"), align="R")
    pdf.set_xy(L, 21)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(W, 6, _t(f"Hirz evidence report  {b['evidence_id']}   captured {b['captured_at']} UTC"))
    pdf.set_xy(L, 40)

    para("Link examined", 9, "B", 5, (90, 90, 90))
    para(b.get("url"), 11, "B", 5.5)
    if b.get("host"):
        para(f"Real domain: {b.get('reg_domain')}   (full host: {b.get('host')})", 9, "", 5, (70, 70, 70))
    pdf.ln(2)
    para(meaning, 11, "", 5.5)
    pdf.ln(2)

    para("Why it was flagged", 12, "B", 6)
    reasons = b.get("reasons") or []
    if not reasons:
        para("No specific warning signs were reported.", 10)
    for r in reasons:
        mark = "+" if r.get("direction") == "safe" else "-"
        para(f" {mark}  {r.get('text') or r.get('code')}", 11, "", 6)
    pdf.ln(2)

    # screenshot
    para("Screenshot", 12, "B", 6)
    shot = b.get("screenshot_path")
    if shot and pathlib.Path(shot).exists():
        y = pdf.get_y()
        pdf.image(shot, x=L, y=y, w=W * 0.55, h=62, keep_aspect_ratio=True)
        pdf.set_xy(L, y + 64)
        para(b.get("screenshot_note"), 8, "I", 4, (90, 90, 90))
    else:
        para(b.get("screenshot_note") or "No screenshot captured.", 9, "I", 5, (90, 90, 90))
    pdf.ln(2)

    # takedown
    para("Where to report it (most effective first)", 12, "B", 6)
    for t in b.get("takedown") or []:
        if t.get("rank") == 4 and not t.get("applies"):
            continue
        bits = [t.get("name"), t.get("email"), t.get("phone"), t.get("url"), t.get("note")]
        para(f"{t['rank']}. {t['target']}: " + "  ".join(x for x in bits if x), 9, "", 4.6)
    pdf.ln(2)

    # technical appendix
    pdf.set_draw_color(200, 200, 200)
    pdf.line(L, pdf.get_y(), L + W, pdf.get_y())
    pdf.ln(1.5)
    para("Technical appendix", 10, "B", 5)
    reg, cert, host = b.get("registration") or {}, b.get("certificate") or {}, b.get("hosting") or {}
    lines = []
    if reg.get("found"):
        lines.append(f"Registration: registrar {reg.get('registrar') or '?'} (IANA {reg.get('registrar_iana_id') or '?'}); "
                     f"created {reg.get('created')} ({reg.get('age_days')} days ago); expires {reg.get('expires')}; "
                     f"nameservers {', '.join(reg.get('nameservers') or []) or '-'}")
    else:
        lines.append(f"Registration: {reg.get('note', 'not found')}")
    if cert.get("found"):
        lines.append(f"Certificate: issuer {cert.get('issuer')}; organisation {cert.get('organisation')}; "
                     f"valid {cert.get('valid_from')} to {cert.get('valid_to')}; covers {cert.get('san_count')} names")
    else:
        lines.append(f"Certificate: {cert.get('note', 'not retrieved')}")
    lines.append(f"Hosting: IP {host.get('ip') or '-'}; AS{host.get('asn') or '?'} {host.get('as_name') or ''}"
                 + (f"; {host['note']}" if host.get("note") else ""))
    chain = b.get("redirect_chain") or []
    lines.append("Redirects: " + (" -> ".join(f"{c['url']} [{c['status']}]" for c in chain[:5]) or "none recorded")
                 + (f"; {b['page_note']}" if b.get("page_note") else ""))
    lines.append(f"Page HTML SHA-256: {b.get('html_sha256') or 'not captured'}")
    if b.get("screenshot_sha256"):
        lines.append(f"Screenshot SHA-256: {b['screenshot_sha256']}")
    lines.append(f"Checked {b.get('checked_at')}; evidence captured {b.get('captured_at')} (UTC)")
    lines.append(f"Bundle SHA-256 (chain of custody, over the canonical JSON of all other fields): {b['bundle_sha256']}")
    for line in lines:
        para(line, 7.5, "", 3.8, (60, 60, 60))
    para("Risk assessments are advisory and are not proof of fraud. Verify with "
         "'python evidence.py --verify <file>.json'.", 7.5, "I", 3.8, (110, 110, 110))
    pdf.output(str(path))
    return str(path)


# ---------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description="Build a police-ready evidence package for a URL.")
    ap.add_argument("url", nargs="?")
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--verify", metavar="JSON")
    a = ap.parse_args()

    if a.verify:
        b = json.loads(pathlib.Path(a.verify).read_text("utf-8"))
        ok = verify(b)
        print(("OK  " if ok else "FAIL") + f"  bundle_sha256 {b.get('bundle_sha256')}")
        sys.exit(0 if ok else 1)
    if not a.url:
        ap.error("give a URL, or --verify FILE")

    try:
        resp = httpx.post(a.api.rstrip("/") + "/check", json={"url": a.url, "deep": True}, timeout=60)
        resp.raise_for_status()
    except Exception as e:
        sys.exit(f"Could not reach the API at {a.api} ({type(e).__name__}). Start it with: uvicorn api:app --port 8000")

    b = build(resp.json())
    OUT.mkdir(exist_ok=True)
    jpath = OUT / f"{b['evidence_id']}.json"
    jpath.write_text(json.dumps(b, indent=2, ensure_ascii=False), "utf-8")
    ppath = render_pdf(b, OUT / f"{b['evidence_id']}.pdf")
    reg = b["takedown"][0]
    print(f"{b['verdict'].upper()} ({b['score']}/100)  {b['url']}")
    print(f"  JSON  {jpath}\n  PDF   {ppath}")
    print(f"  registrar abuse: {reg['name']}  {reg.get('email') or reg.get('note')}")
    print(f"  screenshot: {b['screenshot_path'] or b['screenshot_note']}")
    print(f"  bundle_sha256 {b['bundle_sha256']}  (verify: python evidence.py --verify {jpath})")


if __name__ == "__main__":
    main()
