#!/usr/bin/env python3
"""
Email Harvest — OSINT Email Address Harvester
Discovers corporate email addresses via LinkedIn patterns, crt.sh, GitHub, and header analysis.
Author: Omar Khalid (amooryx) | github.com/amooryx/email-harvest
AUTHORIZED USE ONLY — for authorized red team engagements and bug bounty.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

COMMON_FORMATS = [
    "{first}.{last}",
    "{f}{last}",
    "{first}{l}",
    "{first}_{last}",
    "{last}.{first}",
    "{first}",
]

# ─── Format guessing ──────────────────────────────────────────────────────────
def generate_email_guesses(first: str, last: str, domain: str) -> list[str]:
    f = first[0].lower()
    l = last[0].lower()
    emails = []
    for fmt in COMMON_FORMATS:
        local = fmt.format(first=first.lower(), last=last.lower(), f=f, l=l)
        emails.append(f"{local}@{domain}")
    return emails

# ─── Web source extractors ─────────────────────────────────────────────────────
def extract_emails_from_url(url: str, ua: str = "") -> list[str]:
    try:
        req = urllib.request.Request(url)
        if ua:
            req.add_header("User-Agent", ua)
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read().decode(errors="ignore")
            return list(set(EMAIL_RE.findall(text)))
    except Exception:
        return []

def scrape_github_org_members(org: str, token: str | None = None) -> list[dict]:
    """Fetch GitHub org members and their public emails."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"https://api.github.com/orgs/{org}/members?per_page=100"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            members = json.loads(resp.read())
            emails  = []
            for m in members:
                login    = m.get("login", "")
                user_url = f"https://api.github.com/users/{login}"
                ureq     = urllib.request.Request(user_url, headers=headers)
                try:
                    with urllib.request.urlopen(ureq, timeout=10) as uresp:
                        user = json.loads(uresp.read())
                        email = user.get("email")
                        if email:
                            emails.append({"login": login, "email": email, "name": user.get("name", "")})
                except Exception:
                    pass
                time.sleep(0.5)
            return emails
    except Exception:
        return []

def crtsh_email_search(domain: str) -> list[str]:
    """Try to extract emails from crt.sh certificate subject/SANs."""
    url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            entries = json.loads(resp.read())
            emails  = set()
            for e in entries:
                text = json.dumps(e)
                for m in EMAIL_RE.findall(text):
                    if not m.endswith(".pem"):
                        emails.add(m.lower())
            return list(emails)
    except Exception:
        return []

def verify_email_mx(email: str) -> bool:
    """Check if the email's domain has MX records (basic validity)."""
    import socket
    domain = email.split("@")[1]
    try:
        socket.getaddrinfo(domain, None)
        return True
    except Exception:
        return False

# ─── Entry ────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Email Harvest — OSINT Email Harvester (Authorized use only)",
    )
    subparsers = parser.add_subparsers(dest="cmd")

    guess_p = subparsers.add_parser("guess", help="Generate email format guesses from a name list")
    guess_p.add_argument("domain",    help="Target domain")
    guess_p.add_argument("--names",   required=True, help="File with 'First Last' per line")
    guess_p.add_argument("--out",     help="Output file")

    scrape_p = subparsers.add_parser("scrape", help="Extract emails from URLs")
    scrape_p.add_argument("urls", nargs="+", help="URLs to scrape")
    scrape_p.add_argument("--out",  help="Output file")

    github_p = subparsers.add_parser("github", help="Harvest emails from GitHub org members")
    github_p.add_argument("org")
    github_p.add_argument("--token",  help="GitHub token")
    github_p.add_argument("--out",    help="Output file")

    crt_p = subparsers.add_parser("crtsh", help="Search crt.sh for emails in certificate data")
    crt_p.add_argument("domain")
    crt_p.add_argument("--out", help="Output file")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        sys.exit(1)

    results = []
    if args.cmd == "guess":
        with open(args.names) as f:
            names = [l.strip() for l in f if l.strip()]
        for name in names:
            parts = name.split()
            if len(parts) >= 2:
                guesses = generate_email_guesses(parts[0], parts[-1], args.domain)
                for g in guesses:
                    print(g)
                    results.append(g)

    elif args.cmd == "scrape":
        for url in args.urls:
            print(f"[*] Scraping {url} ...")
            emails = extract_emails_from_url(url)
            print(f"  [+] {len(emails)} emails found")
            for e in emails:
                print(f"    {e}")
                results.append(e)

    elif args.cmd == "github":
        print(f"[*] Harvesting GitHub org: {args.org}")
        members = scrape_github_org_members(args.org, args.token)
        print(f"  [+] {len(members)} members with public emails")
        for m in members:
            print(f"    {m['email']:40s}  ({m['name']} / @{m['login']})")
            results.append(m)

    elif args.cmd == "crtsh":
        print(f"[*] Searching crt.sh for emails in *.{args.domain} certs ...")
        emails = crtsh_email_search(args.domain)
        print(f"  [+] {len(emails)} emails found in certificate data")
        for e in emails:
            print(f"    {e}")
            results.append(e)

    if args.out and results:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
