"""
Feature extraction + dataset builder.
  import : string_feats, reg_of, age_bucket
  run    : python features.py   ->  data/features.csv, data/rules.csv
"""
import math, re

import tldextract

CHEAP_TLDS = {"xyz","top","click","cfd","icu","rest","buzz","sbs","shop",
              "online","site","live","fun","quest","cyou","lol","bond"}
FREE_HOSTS = ("pages.dev","web.app","firebaseapp.com","workers.dev","netlify.app",
              "github.io","vercel.app","r2.dev","glitch.me","repl.co","000webhostapp.com")
KEYWORDS   = {"secure","login","verify","account","update","confirm","signin",
              "wallet","payment","customs","delivery","tracking","parcel","refund",
              "clearance","redelivery","suspended","unlock","reactivate",
              # Arabic transliterations used in UAE-targeted campaigns
              "tahaqoq","hisab","dafa","tawsil","jumruk","khidma","tasjeel"}

# Arabic urgency / account vocabulary, matched against page text not the domain
ARABIC_KEYWORDS = {"تحقق", "عاجل", "تعليق", "الحساب", "تأكيد", "تحديث",
                   "الجمارك", "شحنة", "توصيل", "دفع", "رسوم", "بطاقة"}
BRANDS     = {"adcb","emiratesnbd","enbd","fab","mashreq","rakbank","adib","dib",
              "uaepass","tamm","aramex","dhl","fedex","emiratespost","etisalat","du",
              "dewa","noon","talabat","careem","amazon","paypal","apple","microsoft"}

SPLIT = re.compile(r"[^a-z0-9]+")
def toks(s): return [t for t in SPLIT.split(s.lower()) if t]

def entropy(s):
    if not s: return 0.0
    return -sum((p := s.count(c)/len(s)) * math.log2(p) for c in set(s))

def reg_of(host):
    e = tldextract.extract(host)
    return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else host

def age_bucket(days):
    """0 <7d  1 <30d  2 <90d  3 <1y  4 <3y  5 older   -1 unknown"""
    if days is None or days < 0: return -1
    for i, lim in enumerate([7, 30, 90, 365, 1095]):
        if days < lim: return i
    return 5

def mixed_script(label):
    """A single label mixing Arabic/Latin/Cyrillic is never legitimate."""
    import unicodedata
    scripts = set()
    for c in label:
        if not c.isalpha():
            continue
        name = unicodedata.name(c, "")
        for s in ("ARABIC", "LATIN", "CYRILLIC", "GREEK", "HEBREW"):
            if name.startswith(s):
                scripts.add(s)
    return len(scripts) > 1


def string_feats(host):
    host = host.lower().strip(".")
    e = tldextract.extract(host)
    dom, sub = e.domain, e.subdomain
    suf = e.suffix
    dtok, stok = toks(dom), toks(sub)
    nd = sum(c.isdigit() for c in dom)
    return {
        "dom_len":      len(dom),
        "n_hyphens":    dom.count("-"),
        "n_digits":     nd,
        "digit_ratio":  nd / max(len(dom), 1),
        "n_tokens":     len(dtok),
        "entropy":      round(entropy(dom), 3),
        "is_punycode":  int(dom.startswith("xn--")),
        "cheap_tld":    int(suf.split(".")[-1] in CHEAP_TLDS),
        "free_host":    int(host.endswith(FREE_HOSTS)),
        "kw_in_dom":    int(bool(KEYWORDS & set(dtok))),
        "brand_in_dom": int(bool(BRANDS & set(dtok))),
        "_rule_brand_misplaced": int(bool(BRANDS & set(stok)) and not (BRANDS & set(dtok))),
        "_rule_kw_in_sub":       int(bool(KEYWORDS & set(stok))),
        "_rule_deep_sub":        int(len([l for l in sub.split(".") if l]) >= 3),
        "_rule_mixed_script":    int(any(mixed_script(l) for l in host.split("."))),
    }

if __name__ == "__main__":
    import pandas as pd

    df = pd.read_csv("data/dataset.csv")
    df["reg"] = df["host"].map(reg_of)
    S = pd.DataFrame([string_feats(h) for h in df["host"]])

    rd = pd.read_csv("data/rdap.csv").rename(columns={"domain": "reg"})
    M = df[["reg"]].merge(rd, on="reg", how="left")

    S["rdap_found"]   = M["rdap_found"].fillna(0).astype(int).values
    S["age_bucket"]   = M["age_days"].map(age_bucket).values
    S["expiry_short"] = M["expiry_days"].fillna(-1).between(0, 365).astype(int).values
    S["ns_count"]     = M["ns_count"].fillna(0).clip(upper=10).astype(int).values

    rules = S[[c for c in S.columns if c.startswith("_rule")]].copy()
    rules["host"] = df["host"].values
    rules.to_csv("data/rules.csv", index=False)

    F = S.drop(columns=[c for c in S.columns if c.startswith("_rule")])
    F["label"] = df["label"].values
    F.to_csv("data/features.csv", index=False)

    cov = F.groupby("label")["rdap_found"].mean()
    print(f"RDAP coverage  benign {cov.get(0,0):.0%}  phishing {cov.get(1,0):.0%}")
    print(f"\n{len(F)} rows, {len(F.columns)-1} features")
    print(F.groupby("label").mean().T.round(3))