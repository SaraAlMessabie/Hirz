"""
Re-filter detection files against the CURRENT rules.
Older runs predate the EV / name-validation / free-host fixes, so they contain
the brands' own domains. This drops them without re-running crt.sh.

  python clean_detections.py            # report only
  python clean_detections.py --apply    # rewrite the files (keeps a .bak)
"""
import re, shutil, sys
import pandas as pd

try:
    import tldextract
except ImportError:        # the two strongest rules below do not need it
    tldextract = None

FILES = ["data/ct_hits.csv", "data/lookalikes_triaged.csv"]

EV_HINTS = ("ev rsa", "ev ecc", "extended validation", " ev ")

# A certificate issued by an organisation that is not a public CA came from a
# private one -- the brand running its own. An attacker cannot get a certificate
# from Deutsche Post's internal CA, so the domain is DHL's. This is as conclusive
# as EV and it caught 155 rows the other rules missed.
# CAs that verify the applicant's legal identity before issuing
OV_CA = ("digicert", "entrust", "globalsign", "thawte", "geotrust", "sectigo ov")

PUBLIC_CA = ("let's encrypt", "letsencrypt", "digicert", "sectigo", "comodo",
             "globalsign", "google trust", "amazon", "zerossl", "buypass",
             "actalis", "entrust", "certum", "ssl.com", "rapidssl", "thawte",
             "geotrust", "starfield", "go daddy", "microsoft", "apple public")


def issuer_org(issuer):
    # callers may have lower-cased the issuer already, so match either case
    m = re.search(r"\bO=([^,]+)", issuer or "", re.I)
    return (m.group(1) if m else "").strip().lower()


def tokens(domain):
    """Labels of a domain, so a brand matches as a word and not as a substring."""
    return set(re.split(r"[.\-_]", (domain or "").lower()))
OV_HINTS = ("digicert", "entrust", "globalsign", "sectigo ov", "thawte")

FREE_HOST_ROOTS = {"pages.dev", "workers.dev", "web.app", "netlify.app",
                   "vercel.app", "github.io", "firebaseapp.com", "r2.dev",
                   "glitch.me", "repl.co", "000webhostapp.com"}

REAL = {"paypal": "paypal.com", "dhl": "dhl.com", "fedex": "fedex.com",
        "netflix": "netflix.com", "whatsapp": "whatsapp.com",
        "aramex": "aramex.com", "adcb": "adcb.com",
        "emiratesnbd": "emiratesnbd.com", "uaepass": "uaepass.ae",
        "emiratespost": "emiratespost.ae"}


def why_drop(row):
    d = str(row.get("domain") or "").strip().lower()
    brand = str(row.get("brand") or "").lower().replace(".com", "").replace(".ae", "")
    issuer = str(row.get("issuer") or "").lower()

    if not d or "." not in d or " " in d or "," in d:
        return "not a domain"
    if d in FREE_HOST_ROOTS:
        return "bare free-host root (collapse bug)"
    # "dhl" inside chcembytvdhl.sk is not a DHL look-alike, it is a bad match
    if brand and brand not in tokens(d):
        return "brand name is only a substring, not a label"
    if any(h in issuer for h in EV_HINTS):
        return "Extended Validation certificate - verified legal identity"
    org = issuer_org(issuer)
    if org and not any(pub in org for pub in PUBLIC_CA):
        return f"issued by a private CA ({org[:40]}) - the brand's own"
    # a brand gTLD: DHL owns .dhl, so finance.dhl can only be DHL
    if brand and d.rsplit(".", 1)[-1] == brand:
        return f"on the brand's own top-level domain (.{brand})"
    # An OV certificate means the CA checked the applicant's legal identity.
    # Brand name plus verified identity is the brand; scams sit on DV certs,
    # which prove control of the domain and nothing about who is behind it.
    if any(ov in org for ov in OV_CA) and brand in tokens(d):
        return f"brand name on an identity-checked (OV) certificate from {org[:24]}"
    # the brand's own domain: domain label == brand, any TLD
    if tldextract is not None and tldextract.extract(d).domain == brand:
        return f"the brand's own domain ({brand})"
    # brand's country sites: brand-<country>.<cctld> on an OV issuer
    if any(h in issuer for h in OV_HINTS) and brand and brand in d:
        parts = d.split(".")
        if len(parts) >= 2 and len(parts[-1]) == 2:
            return "brand country site on an OV certificate"
    return None


if __name__ == "__main__":
    apply = "--apply" in sys.argv
    for path in FILES:
        try:
            df = pd.read_csv(path)
        except Exception:
            print(f"{path}: not found, skipping"); continue

        reasons = df.apply(why_drop, axis=1)
        drop = reasons.notna()
        kept = df[~drop]

        print(f"\n{path}: {len(df)} rows -> {len(kept)} kept, {int(drop.sum())} dropped")
        if drop.sum():
            summary = reasons[drop].value_counts()
            for why, n in summary.items():
                print(f"   {n:>4}  {why}")
            print("\n   examples:")
            for d, why in zip(df[drop].domain.head(10), reasons[drop].head(10)):
                print(f"     {str(d)[:46]:46} {why}")

        if apply and drop.sum():
            shutil.copy(path, path + ".bak")
            kept.to_csv(path, index=False)
            print(f"   rewrote {path}  (backup at {path}.bak)")

    if not apply:
        print("\nReport only. Re-run with --apply to rewrite the files.")
    else:
        print("\nDone. Restart the API so it reloads the cleaned files.")
