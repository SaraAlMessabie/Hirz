"""
Evidence package (Task 4).

  build(check_response) -> dict      bundle with a chain-of-custody hash
  verify(bundle) -> bool             recompute bundle_sha256

  python evidence.py <url>           calls POST /check, writes evidence/<id>.json and
                                     <id>.pdf (page 1 English, page 2 Arabic)
  python evidence.py --verify evidence/<id>.json

Options:  --api http://127.0.0.1:8000   where api.py is running
Env:      URLSCAN_API_KEY               optional; adds a screenshot via urlscan.io

The page is fetched once with a plain HTTP GET (no JavaScript is run).
If something can't be collected, the field says so — nothing is invented.
"""
import argparse, hashlib, json, os, pathlib, socket, ssl, sys, time, uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlparse

import httpx

from tier2 import bootstrap, reg_of

# Anchored to the repo: the servers import this module and may be started
# from any directory.
ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT / "evidence"
RDAP_CACHE = ROOT / "cache" / "rdap"
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
ASSETS = pathlib.Path(__file__).resolve().parent / "assets"
LOGO = ASSETS / "hirz_logo.png"
FONT_REG = ASSETS / "fonts" / "DejaVuSans.ttf"
FONT_BOLD = ASSETS / "fonts" / "DejaVuSans-Bold.ttf"
NAVY = (11, 22, 41)

VERDICT_COLOR = {"malicious": (230, 57, 70), "suspicious": (245, 158, 11),
                 "clean": (34, 197, 94), "unknown": (148, 163, 184)}

T = {
    "en": {
        "verdict": {"malicious": "MALICIOUS", "suspicious": "SUSPICIOUS",
                    "clean": "NO WARNINGS", "unknown": "UNKNOWN"},
        "meaning": {
            "malicious": "This link shows strong signs of a scam designed to steal personal or payment details.",
            "suspicious": "This link shows some warning signs and should be treated with caution.",
            "clean": "No warning signs were found. This does not guarantee the link is safe.",
            "unknown": "The link could not be assessed."},
        "title": "Hirz evidence report", "captured": "captured", "score": "Risk score",
        "link": "Link examined", "real": "Real domain", "full": "full host",
        "why": "Why it was flagged", "none": "No specific warning signs were reported.",
        "shot": "Screenshot", "noshot": None,
        "report": "Where to report it (most effective first)",
        "appendix": "Technical appendix",
        "disclaimer": "Risk assessments are advisory and are not proof of fraud.",
        "targets": {}, "notes": {},
    },
    "ar": {
        "verdict": {"malicious": "احتيالي", "suspicious": "مشبوه",
                    "clean": "لا توجد تحذيرات", "unknown": "غير معروف"},
        "meaning": {
            "malicious": "تظهر على هذا الرابط مؤشرات قوية على أنه احتيال يهدف إلى سرقة البيانات الشخصية أو بيانات الدفع.",
            "suspicious": "تظهر على هذا الرابط بعض المؤشرات التحذيرية، ويجب التعامل معه بحذر.",
            "clean": "لم يتم العثور على مؤشرات تحذيرية. هذا لا يضمن أن الرابط آمن.",
            "unknown": "تعذر تقييم هذا الرابط."},
        "title": "تقرير أدلة حرز", "captured": "تاريخ الالتقاط", "score": "درجة الخطورة",
        "link": "الرابط الذي تم فحصه", "real": "النطاق الحقيقي", "full": "العنوان الكامل",
        "why": "أسباب التصنيف", "none": "لم يتم الإبلاغ عن مؤشرات تحذيرية محددة.",
        "shot": "لقطة الشاشة", "noshot": "لم تلتقط لقطة شاشة.",
        "shot_ok": "التقطت بواسطة urlscan.io (ماسح مستقل).",
        "report": "جهات الإبلاغ (الأكثر فعالية أولا)",
        "appendix": "الملحق التقني (بالإنجليزية)",
        "disclaimer": "تقييمات المخاطر استرشادية وليست دليلا على الاحتيال.",
        "targets": {1: "جهة تسجيل النطاق (قسم البلاغات)", "host": "مزود الاستضافة",
                    "cf": "Cloudflare (وسيط أمام الخادم الحقيقي)", 3: "التصفح الآمن من Google",
                    4: "ملف قضية للشرطة"},
        "notes": {"RDAP listed no abuse contact; use the registrar's website.":
                      "لم يدرج سجل RDAP جهة اتصال للبلاغات؛ استخدم موقع جهة التسجيل.",
                  "No network abuse contact found.": "لم يعثر على جهة اتصال للبلاغات لدى الشبكة.",
                  "Submit this PDF through official AD Police channels.":
                      "يقدم هذا التقرير عبر القنوات الرسمية لشرطة أبوظبي."},
    },
}

# Arabic for the reason codes api.py returns; unknown codes fall back to the English text.
REASON_AR = {
    "free_host": "مستضاف على منصة مجانية تصدر شهادات HTTPS فورية",
    "cheap_tld": "يستخدم امتداد نطاق رخيصا يشتريه المحتالون بكميات كبيرة",
    "n_hyphens": "اسم النطاق محشو بشرطات",
    "dom_len": "اسم نطاق طويل بشكل غير معتاد",
    "entropy": "اسم النطاق يبدو مولدا عشوائيا",
    "n_digits": "أرقام مضافة إلى اسم النطاق",
    "digit_ratio": "نسبة عالية من الأرقام في اسم النطاق",
    "brand_in_dom": "يحتوي على اسم علامة تجارية محمية",
    "kw_in_dom": "كلمات أمنية في اسم النطاق",
    "mobile_prefix": "رقم هاتف متحرك شخصي، بينما تنشر البنوك وشركات الشحن والجهات الحكومية في الإمارات أرقاما مجانية أو أرضية",
    "not_in_official_set": "ليس من الأرقام المنشورة رسميا للجهة",
    "official": "يطابق رقم خدمة العملاء المنشور للجهة",
    "ct_free_ca": "الشهادة صادرة عن جهة مجانية",
    "ct_age_bucket": "صدرت شهادة النطاق حديثا جدا",
    "ct_max_san": "الشهادة تغطي عددا كبيرا من النطاقات غير المرتبطة (إصدار بالجملة)",
    "ct_found": "لم يعثر على سجل للشهادات",
    "_rule_brand_misplaced": "اسم العلامة التجارية يظهر في النطاق الفرعي بينما النطاق الحقيقي مختلف",
    "_rule_kw_in_sub": "كلمات أمنية مستخدمة في النطاق الفرعي",
    "_rule_deep_sub": "تداخل غير معتاد في النطاقات الفرعية",
}


HEADER_BG = ASSETS / "header_bg.png"
LOGO_SOFT = ASSETS / "hirz_logo_soft.png"
CYAN = (8, 145, 178)                     # print-safe version of the slide's glow colour
UAE = [(0, 115, 47), (255, 255, 255), (0, 0, 0), (206, 17, 38)]


UAE_TZ = timezone(timedelta(hours=4), "GST")      # UAE has no daylight saving


def uae_time(iso, lang="en"):
    """'2026-11-24T15:20:32+00:00' -> '24 Nov 2026, 19:20:32 UAE time' (bundle stays in UTC)."""
    try:
        t = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        t = t.astimezone(UAE_TZ)
    except Exception:
        return str(iso or "-")
    if lang == "ar":
        return t.strftime("%Y-%m-%d %H:%M:%S") + " بتوقيت الإمارات"
    return t.strftime("%d %b %Y, %H:%M:%S") + " UAE time"


def render_pdf(b: dict, path):
    """One PDF: page 1 English, page 2 Arabic (right-to-left)."""
    from fpdf import FPDF
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(False)
    pdf.set_margins(14, 12, 14)
    if not (FONT_REG.exists() and FONT_BOLD.exists()):
        raise RuntimeError("Missing assets/fonts/DejaVuSans*.ttf (needed for Arabic)")
    pdf.add_font("Hirz", "", str(FONT_REG))
    pdf.add_font("Hirz", "B", str(FONT_BOLD))
    for page, lang in enumerate(("en", "ar"), 1):
        _render_page(pdf, b, lang, page)
    pdf.output(str(path))
    return str(path)


def _render_page(pdf, b, lang, page_no, pages=2):
    from arabic_text import visual
    L10N, rtl = T[lang], lang == "ar"
    pdf.add_page()
    W, L = pdf.w - pdf.l_margin - pdf.r_margin, pdf.l_margin
    R = L + W
    show = (lambda s: visual(str(s))) if rtl else str

    def font(size, style=""):
        pdf.set_font("Hirz", "B" if "B" in style else "", size)

    def wrap(text, width):
        words, lines, cur = [], [], ""
        for w in str(text if text is not None else "").split(" "):   # hard-split long URLs
            while pdf.get_string_width(w) > width and len(w) > 1:
                k = len(w)
                while k > 1 and pdf.get_string_width(w[:k]) > width:
                    k -= 1
                words.append(w[:k]); w = w[k:]
            words.append(w)
        for w in words:
            t = f"{cur} {w}" if cur else w
            if cur and pdf.get_string_width(visual(t) if rtl else t) > width:
                lines.append(cur); cur = w
            else:
                cur = t
        return lines + [cur]

    def para(text, size=10, style="", h=5, color=(30, 30, 30), ltr=False, indent=0):
        font(size, style)
        pdf.set_text_color(*color)
        y = pdf.get_y()
        x, width = (L, W - indent) if rtl else (L + indent, W - indent)
        for line in wrap(text, width):
            pdf.set_xy(x, y)
            if rtl and not ltr:
                pdf.cell(width, h, visual(line), align="R")
            else:
                pdf.cell(width, h, line)
            y += h
        pdf.set_xy(L, y)

    def heading(text):
        y = pdf.get_y() + 1
        pdf.set_fill_color(*CYAN)
        pdf.rect(R - 1.2 if rtl else L, y + 1, 1.2, 4.6, "F")      # accent bar on the reading side
        pdf.set_xy(L, y)
        para(text, 12, "B", 6.5, (15, 23, 42), indent=3.5)

    v = b.get("verdict") if b.get("verdict") in VERDICT_COLOR else "unknown"
    vcol = VERDICT_COLOR[v]
    score = b.get("score") if isinstance(b.get("score"), (int, float)) else None

    # ---- header: network band, soft logo, verdict + meter, corner marks
    if HEADER_BG.exists():
        pdf.image(str(HEADER_BG), x=0, y=0, w=pdf.w, h=40)
    else:
        pdf.set_fill_color(*NAVY); pdf.rect(0, 0, pdf.w, 40, "F")
    logo_h, logo_w = 34, 0
    logo = LOGO_SOFT if LOGO_SOFT.exists() else LOGO
    if logo.exists():
        from PIL import Image
        with Image.open(logo) as im:
            logo_w = logo_h * im.width / im.height
        pdf.image(str(logo), x=(R - logo_w) if rtl else L - 2, y=3, w=logo_w, h=logo_h)
    pdf.set_draw_color(226, 232, 240); pdf.set_line_width(0.5)
    for cx, sign in ((4, 1), (pdf.w - 4, -1)):                     # "////" corner marks from the slide
        for k in range(4):
            x0 = cx + sign * k * 1.6
            pdf.line(x0, 7, x0 + sign * 1.2, 4)
    tx, tw = (L, W - logo_w - 4) if rtl else (L + logo_w + 2, W - logo_w - 2)
    align = "L" if rtl else "R"
    font(24, "B"); pdf.set_text_color(*vcol); pdf.set_xy(tx, 6)
    pdf.cell(tw, 12, show(L10N["verdict"][v]), align=align)
    font(12, "B"); pdf.set_text_color(255, 255, 255); pdf.set_xy(tx, 18.5)
    pdf.cell(tw, 6, show(f"{L10N['score']} {b.get('score', '-')}/100"), align=align)
    mw = 46                                                          # score meter, like the web page
    mx = tx if rtl else tx + tw - mw
    pdf.set_fill_color(51, 65, 85); pdf.rect(mx, 26.3, mw, 1.8, "F")
    if score is not None:
        fill = mw * max(0, min(100, score)) / 100
        pdf.set_fill_color(*vcol); pdf.rect(mx + mw - fill if rtl else mx, 26.3, fill, 1.8, "F")
    font(7.5); pdf.set_text_color(190, 205, 222); pdf.set_xy(tx, 30.5)
    pdf.cell(tw, 4.5, show(f"{L10N['title']}  {b['evidence_id']}  ·  {L10N['captured']} {uae_time(b['captured_at'], lang)}"),
             align=align)
    seg = pdf.w / 4                                                  # UAE-flag stripe, as on the logo
    for i, col in enumerate(reversed(UAE) if rtl else UAE):
        pdf.set_fill_color(*col); pdf.rect(i * seg, 40, seg, 1.6, "F")
    pdf.set_draw_color(220, 220, 220); pdf.set_line_width(0.2)
    pdf.line(0, 41.6, pdf.w, 41.6)
    pdf.set_xy(L, 47)

    # ---- body
    para(L10N["link"], 9, "B", 5, (100, 116, 139))
    para(b.get("url"), 11, "B", 5.5, ltr=not rtl)
    if b.get("host"):
        para(f"{L10N['real']}: {b.get('reg_domain')}   ({L10N['full']}: {b.get('host')})", 9, "", 5, (71, 85, 105))
    pdf.ln(2)
    para(L10N["meaning"][v], 11, "", 5.5)
    pdf.ln(1)

    heading(L10N["why"])
    reasons = b.get("reasons") or []
    if not reasons:
        para(L10N["none"], 10)
    for r in reasons:
        mark = "✓" if r.get("direction") == "safe" else "•"
        text = (REASON_AR.get(r.get("code")) if rtl else None) or r.get("text") or r.get("code")
        para(f"{mark}  {text}", 11, "", 6, indent=3.5)
    pdf.ln(1)

    heading(L10N["shot"])
    shot = b.get("screenshot_path")
    if shot and pathlib.Path(shot).exists():
        y, sw = pdf.get_y(), W * 0.55
        pdf.image(shot, x=(R - sw) if rtl else L, y=y, w=sw, h=62, keep_aspect_ratio=True)
        pdf.set_xy(L, y + 64)
        para(L10N.get("shot_ok") if rtl else b.get("screenshot_note"), 8, "", 4, (100, 116, 139), indent=3.5)
    else:
        para(L10N["noshot"] or b.get("screenshot_note") or "No screenshot captured.", 9, "", 5,
             (100, 116, 139), indent=3.5)
    pdf.ln(1)

    heading(L10N["report"])
    for t in b.get("takedown") or []:
        if t.get("rank") == 4 and not t.get("applies"):
            continue
        name = t["target"]
        if rtl:
            key = "cf" if "Cloudflare" in name else ("host" if t["rank"] == 2 else t["rank"])
            name = L10N["targets"].get(key, name)
        note = L10N["notes"].get(t.get("note"), t.get("note")) if rtl else t.get("note")
        bits = [t.get("name") if t["rank"] in (1, 2) else "", t.get("email"), t.get("phone"), t.get("url"), note]
        para(f"{t['rank']}. {name}: " + "  ".join(x for x in bits if x), 9, "", 4.6, indent=3.5)
    pdf.ln(2)

    # ---- technical appendix (English on both pages: identifiers, hashes, dates)
    pdf.set_draw_color(203, 213, 225); pdf.set_line_width(0.2)
    pdf.line(L, pdf.get_y(), R, pdf.get_y())
    pdf.ln(1.5)
    para(L10N["appendix"], 10, "B", 5, (15, 23, 42))
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
    lines.append(f"Screenshot: {b.get('screenshot_note') or '-'}")
    lines.append(f"Page HTML SHA-256: {b.get('html_sha256') or 'not captured'}")
    if b.get("screenshot_sha256"):
        lines.append(f"Screenshot SHA-256: {b['screenshot_sha256']}")
    lines.append(f"Checked {uae_time(b.get('checked_at'))}; evidence captured {uae_time(b.get('captured_at'))} "
                 "(UTC+4; the JSON bundle stores UTC)")
    lines.append(f"Bundle SHA-256 (chain of custody, over the canonical JSON of all other fields): {b['bundle_sha256']}")
    for line in lines:
        para(line, 7.5, "", 3.8, (71, 85, 105), ltr=True)
    para(L10N["disclaimer"], 7.5, "", 3.8, (100, 116, 139))

    # ---- footer
    pdf.set_draw_color(*CYAN); pdf.set_line_width(0.4)
    pdf.line(L, 284, R, 284)
    font(7.5); pdf.set_text_color(100, 116, 139)
    pdf.set_xy(L, 285.5)
    pdf.cell(W / 2, 4, f"Hirz  |  {b['evidence_id']}  |  verify: python evidence.py --verify {b['evidence_id']}.json")
    pdf.set_xy(L + W / 2, 285.5)
    pdf.cell(W / 2, 4, visual(f"حرز  ·  {page_no}/{pages}"), align="R")


def save(b: dict):
    """Write evidence/<id>.json and evidence/<id>.pdf; returns both paths."""
    OUT.mkdir(exist_ok=True)
    jpath = OUT / f"{b['evidence_id']}.json"
    jpath.write_text(json.dumps(b, indent=2, ensure_ascii=False), "utf-8")
    return jpath, render_pdf(b, OUT / f"{b['evidence_id']}.pdf")


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
    jpath, ppath = save(b)
    reg = b["takedown"][0]
    print(f"{b['verdict'].upper()} ({b['score']}/100)  {b['url']}")
    print(f"  JSON  {jpath}\n  PDF   {ppath}  (page 1 English, page 2 Arabic)")
    print(f"  registrar abuse: {reg['name']}  {reg.get('email') or reg.get('note')}")
    print(f"  screenshot: {b['screenshot_path'] or b['screenshot_note']}")
    print(f"  bundle_sha256 {b['bundle_sha256']}  (verify: python evidence.py --verify {jpath})")


if __name__ == "__main__":
    main()
