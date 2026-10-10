#!/usr/bin/env python3
# ---------------------------------------------------------
# Network fetch helper for revanced-magisk-module's utils.sh.
#
# The request/retry/challenge-detection shape here is adapted from
# krvstek/uni-apks's NetworkManager (src/core/network.py),
# https://github.com/krvstek/uni-apks — Copyright (C) 2026 krvstek,
# licensed GNU GPLv3. This is an independent reimplementation as a
# standalone CLI (no dependency on the rest of that package), written
# for a different project's bash build pipeline.
#
# What this DOES fix: 403s caused by TLS/JA3 fingerprinting and
# missing browser-like session behavior, via curl_cffi's Chrome
# impersonation (something plain curl cannot replicate).
#
# What this does NOT do: solve an actual Cloudflare JS/Turnstile
# challenge on its own. If CF_SOLVER_URL is set, it will call out to
# a FlareSolverr-compatible solver for cookies, exactly like upstream
# does — but that solver is separate infrastructure you'd have to run
# yourself; this script does not implement one.
# ---------------------------------------------------------

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path

try:
    from curl_cffi import requests
    from curl_cffi.requests import exceptions as req_exc
except ImportError:
    sys.stderr.write(
        "apk_fetch.py: curl_cffi is not installed.\n"
        "Install it with: pip install curl_cffi --break-system-packages\n"
        "(or inside a venv, without that flag)\n"
    )
    sys.exit(1)

IMPERSONATE = os.environ.get("CURL_CFFI_IMPERSONATE", "chrome124")
RETRY_DELAYS = (2, 4)
MAX_ATTEMPTS = len(RETRY_DELAYS) + 1
SOLVER_URL = os.environ.get("CF_SOLVER_URL")

# Exit codes: 0 = success, 1 = failed after retries, 2 = 404 (caller
# treats this as "resource genuinely doesn't exist", not a retryable error)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def load_cookies(session, jar_path: str | None) -> None:
    if not jar_path or not Path(jar_path).exists():
        return
    try:
        data = json.loads(Path(jar_path).read_text())
        for k, v in data.items():
            session.cookies.set(k, v)
    except Exception as exc:
        eprint(f"cookie jar load failed ({jar_path}): {exc}")


def save_cookies(session, jar_path: str | None) -> None:
    if not jar_path:
        return
    try:
        Path(jar_path).write_text(json.dumps(dict(session.cookies)))
    except Exception as exc:
        eprint(f"cookie jar save failed ({jar_path}): {exc}")


def is_challenge(resp) -> bool:
    if resp.status_code == 403:
        return True
    if resp.status_code == 503:
        body = (resp.text or "").lower()
        return "just a moment" in body or "turnstile" in body or "cf-mitigated" in resp.headers
    return False


def solve_challenge(session, url: str) -> bool:
    if not SOLVER_URL:
        return False
    try:
        r = requests.get(f"{SOLVER_URL}/cookies", params={"url": url}, timeout=60)
        if r.status_code != 200:
            return False
        data = r.json()
        cookies = data.get("cookies", {})
        ua = data.get("user_agent")
        if isinstance(cookies, dict):
            for k, v in cookies.items():
                session.cookies.set(k, v)
        elif isinstance(cookies, list):
            for c in cookies:
                if isinstance(c, dict) and "name" in c and "value" in c:
                    session.cookies.set(c["name"], c["value"])
        if ua:
            session.headers["User-Agent"] = ua
        return True
    except Exception as exc:
        eprint(f"solver error for {url}: {exc}")
        return False


def retry_sleep(attempt: int) -> None:
    if attempt <= len(RETRY_DELAYS):
        time.sleep(RETRY_DELAYS[attempt - 1] + random.uniform(0, 1))


def build_headers(header_args: list[str]) -> dict[str, str]:
    headers = {}
    for h in header_args or []:
        if ":" in h:
            k, v = h.split(":", 1)
            k, v = k.strip(), v.strip()
            if k and v:
                headers[k] = v
    return headers


def do_get(session, url: str, headers: dict, jar_path: str | None) -> tuple[str | None, int]:
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            resp = session.get(url, timeout=(5, 30), allow_redirects=True, headers=headers, verify=True)
        except req_exc.RequestException as exc:
            eprint(f"request error ({attempt}/{MAX_ATTEMPTS}) for {url}: {exc}")
            retry_sleep(attempt)
            continue
        if resp.status_code == 404:
            eprint(f"404 Not Found: {url}")
            return None, 2
        if is_challenge(resp):
            eprint(f"403/challenge for {url}, attempt {attempt}/{MAX_ATTEMPTS}")
            solve_challenge(session, url)
            retry_sleep(attempt)
            continue
        if resp.status_code >= 400:
            eprint(f"HTTP {resp.status_code} for {url}, attempt {attempt}/{MAX_ATTEMPTS}")
            retry_sleep(attempt)
            continue
        save_cookies(session, jar_path)
        return resp.text, 0
    return None, 1


def do_download(session, url: str, dest: str, headers: dict, jar_path: str | None) -> int:
    dest_p = Path(dest)
    tmp = dest_p.with_name(f"tmp.{dest_p.name}")
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            resp = session.get(url, timeout=(5, 300), stream=True, allow_redirects=True, headers=headers, verify=True)
        except req_exc.RequestException as exc:
            eprint(f"download error ({attempt}/{MAX_ATTEMPTS}) for {url}: {exc}")
            retry_sleep(attempt)
            continue
        if resp.status_code == 404:
            eprint(f"404 Not Found: {url}")
            return 2
        if is_challenge(resp):
            eprint(f"403/challenge for {url}, attempt {attempt}/{MAX_ATTEMPTS}")
            solve_challenge(session, url)
            retry_sleep(attempt)
            continue
        if resp.status_code >= 400:
            eprint(f"HTTP {resp.status_code} for {url}, attempt {attempt}/{MAX_ATTEMPTS}")
            retry_sleep(attempt)
            continue
        dest_p.parent.mkdir(parents=True, exist_ok=True)
        with tmp.open("wb") as fh:
            for chunk in resp.iter_content(chunk_size=1048576):
                fh.write(chunk)
        tmp.replace(dest_p)
        save_cookies(session, jar_path)
        return 0
    tmp.unlink(missing_ok=True)
    return 1


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["get", "download"])
    p.add_argument("url")
    p.add_argument("dest", nargs="?", default=None)
    p.add_argument("--cookie-jar", default=None)
    p.add_argument("--header", action="append", default=[])
    args = p.parse_args()

    session = requests.Session(impersonate=IMPERSONATE)
    load_cookies(session, args.cookie_jar)
    headers = build_headers(args.header)

    if args.mode == "get":
        body, code = do_get(session, args.url, headers, args.cookie_jar)
        if code == 0:
            sys.stdout.write(body)
        sys.exit(code)
    else:
        if not args.dest:
            eprint("download mode requires <dest>")
            sys.exit(1)
        sys.exit(do_download(session, args.url, args.dest, headers, args.cookie_jar))


if __name__ == "__main__":
    main()
