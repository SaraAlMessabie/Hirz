"""
Checks the running API behaves correctly. Start uvicorn first.
  python verify.py
"""
import sys, time
import httpx

API = "http://127.0.0.1:8000"
passed = failed = 0


def check(name, got, want, note=""):
    global passed, failed
    ok = got == want
    passed, failed = passed + ok, failed + (not ok)
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}")
    if not ok:
        print(f"         expected {want!r}, got {got!r}")
    if note:
        print(f"         {note}")


def post(path, body, timeout=45):
    try:
        return httpx.post(API + path, json=body, timeout=timeout).json()
    except Exception as e:
        return {"_error": e.__class__.__name__}


print("\n--- 1. is it up ---")
try:
    root = httpx.get(API + "/", timeout=10).json()
    print(f"  features={root.get('features')}  official={root.get('official')}  "
          f"confirmed={root.get('confirmed')}  reported={root.get('reported')}")
    check("API responds", root.get("status"), "ok")
    check("official allowlist loaded", (root.get("official") or 0) > 0, True)
except Exception as e:
    print(f"  API unreachable ({e.__class__.__name__}) - start uvicorn first")
    sys.exit(1)

print("\n--- 2. official allowlist ---")
r = post("/check", {"url": "https://www.adcb.com", "deep": False})
check("a real bank is OFFICIAL", r.get("status"), "OFFICIAL",
      (r.get("reasons") or [{}])[0].get("text", ""))

r = post("/check", {"url": "https://dubaipolice.gov.ae", "deep": False})
check(".gov.ae is OFFICIAL", r.get("status"), "OFFICIAL")

r = post("/check", {"url": "https://tamm.abudhabi.gov.ae.secure-login.xyz/verify",
                    "deep": False})
check("the suffix backdoor is closed", r.get("status") != "OFFICIAL", True,
      f"got status={r.get('status')} - must NOT be OFFICIAL")

print("\n--- 3. discovery is never served as confirmed ---")
d = httpx.get(API + "/detections?limit=1&min_score=80", timeout=20).json()
if d.get("items"):
    dom = d["items"][0]["domain"]
    r = post("/check", {"url": dom, "deep": False})
    check(f"discovery hit is REPORTED not CONFIRMED ({dom[:38]})",
          r.get("status") in ("REPORTED", "SUSPICIOUS", "NO_MATCH"), True,
          f"got {r.get('status')}")
else:
    print("  [skip] no detections loaded")

print("\n--- 4. EV certificate clears a legitimate brand domain ---")
r = post("/check", {"url": "https://paypal-engineering.com"})
check("PayPal's own blog is not malicious", r.get("verdict") != "malicious", True,
      f"status={r.get('status')} score={r.get('score')} "
      f"| {(r.get('reasons') or [{}])[0].get('text','')[:70]}")

print("\n--- 5. no duplicate deep checks ---")
t0 = time.time(); a = post("/check", {"url": "https://example.com"}); t1 = time.time()
b = post("/check", {"url": "https://example.com"}); t2 = time.time()
print(f"  first {t1-t0:.1f}s   second {t2-t1:.1f}s")
check("second request is cached", b.get("cached"), True)
check("cached result is faster", (t2 - t1) < (t1 - t0), True)

print("\n--- 6. absence is never 'safe' ---")
r = post("/check", {"url": "https://a-domain-nobody-has-reported-7731.com",
                    "deep": False})
txt = " ".join(x.get("text", "") for x in (r.get("reasons") or []))
check("unknown domain says so explicitly",
      "does not guarantee" in txt or r.get("status") in ("NO_MATCH", "UNKNOWN"), True,
      f"status={r.get('status')} | {txt[:70]}")
check("advisory present", bool(r.get("advisory")), True)

print("\n--- 7. the review loop ---")
test_dom = "verify-test-domain-7731.xyz"
post("/review", {"domain": test_dom, "decision": "confirm", "reviewer": "verify.py"})
r = post("/check", {"url": test_dom, "deep": False})
check("confirmed domain returns CONFIRMED", r.get("status"), "CONFIRMED")
post("/review", {"domain": test_dom, "decision": "reject", "reviewer": "verify.py"})
r = post("/check", {"url": test_dom, "deep": False})
check("rejected domain is no longer CONFIRMED", r.get("status") != "CONFIRMED", True)

print("\n--- 8. dashboard endpoints ---")
for path in ("/stats", "/detections?limit=5", "/campaigns", "/confirmed",
             "/official", "/reviews"):
    try:
        code = httpx.get(API + path, timeout=20).status_code
    except Exception:
        code = 0
    check(f"GET {path.split('?')[0]}", code, 200)

print(f"\n{'='*46}\n  {passed} passed, {failed} failed\n{'='*46}")
sys.exit(1 if failed else 0)
