#!/usr/bin/env python3
"""Collect in-scope email addresses from explicitly authorized sources."""

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
COMMON_FORMATS = (
    "{first}.{last}",
    "{f}{last}",
    "{first}{l}",
    "{first}_{last}",
    "{last}.{first}",
    "{first}",
)
MAX_URLS = 25
MAX_NAMES = 1000
MAX_RESPONSE_BYTES = 2_000_000
MAX_PAGE_BYTES = 1_000_000
MAX_EMAILS = 5000
MAX_GITHUB_USERS = 100
REQUEST_TIMEOUT = 10
USER_AGENT = "email-harvest/1.0 (authorized security testing)"
EMAIL_HARVEST_HEADERS = {"User-Agent": USER_AGENT}


class HarvestError(Exception):
    """An expected input or remote-service error suitable for CLI output."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RateLimiter:
    def __init__(self, interval: float = 1.0):
        self.interval = interval
        self.last_request: Optional[float] = None

    def wait(self) -> None:
        now = time.monotonic()
        if self.last_request is not None:
            delay = self.interval - (now - self.last_request)
            if delay > 0:
                time.sleep(delay)
        self.last_request = time.monotonic()


def validate_domain(domain: str) -> str:
    try:
        value = domain.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise HarvestError("provide a valid fully qualified domain name") from exc
    labels = value.split(".")
    if (
        len(value) > 253
        or len(labels) < 2
        or any(not DOMAIN_LABEL_RE.fullmatch(label) for label in labels)
        or len(labels[-1]) < 2
        or not (labels[-1].isalpha() or labels[-1].startswith("xn--"))
    ):
        raise HarvestError("provide a valid fully qualified domain name")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise HarvestError("IP addresses are not valid domain scopes")


def host_is_in_scope(host: str, domain: str) -> bool:
    try:
        normalized_host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return False
    return normalized_host == domain or normalized_host.endswith("." + domain)


def validate_org(org: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", org):
        raise HarvestError("provide a valid GitHub organization name")
    return org


def validate_scrape_url(url: str, authorized_domain: str) -> urllib.parse.ParseResult:
    try:
        parsed = urllib.parse.urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise HarvestError(f"URL has an invalid port: {url}") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or port not in (None, 443)
        or not host_is_in_scope(parsed.hostname, authorized_domain)
    ):
        raise HarvestError(
            f"URL must use HTTPS on {authorized_domain} or one of its subdomains: {url}"
        )
    return parsed


def ensure_public_host(host: str) -> None:
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise HarvestError(f"could not resolve host {host}: {exc}") from exc
    if not addresses:
        raise HarvestError(f"host {host} did not resolve to an address")
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address[4][0])
        except ValueError as exc:
            raise HarvestError(f"host {host} resolved to an invalid address") from exc
        if not ip.is_global:
            raise HarvestError(f"refusing to access non-public host {host}")


def request_bytes(
    url: str,
    *,
    headers: Optional[dict[str, str]] = None,
    timeout: int = REQUEST_TIMEOUT,
    max_bytes: int = MAX_RESPONSE_BYTES,
    limiter: Optional[RateLimiter] = None,
) -> tuple[bytes, Any]:
    host = urllib.parse.urlparse(url).hostname
    if not host:
        raise HarvestError("request URL has no hostname")
    ensure_public_host(host)
    if limiter is not None:
        limiter.wait()
    request = urllib.request.Request(url, headers=headers or EMAIL_HARVEST_HEADERS)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirectHandler(),
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > max_bytes:
                        raise HarvestError(
                            f"response from {host} exceeds the {max_bytes}-byte limit"
                        )
                except ValueError as exc:
                    raise HarvestError(f"response from {host} has an invalid content length") from exc
            payload = response.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise HarvestError(f"response from {host} exceeds the {max_bytes}-byte limit")
            return payload, response
    except HarvestError:
        raise
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise HarvestError(f"refusing redirect from {host} (HTTP {exc.code})") from exc
        raise HarvestError(f"request to {host} failed with HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HarvestError(f"request to {host} failed: {exc}") from exc


def parse_json(payload: bytes, source: str) -> Any:
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarvestError(f"{source} returned invalid JSON") from exc


def normalize_email_results(emails: list[str], scope: str) -> list[str]:
    found = []
    seen = set()
    for email in emails:
        normalized = email.strip().lower()
        email_domain = normalized.rsplit("@", 1)[-1]
        if host_is_in_scope(email_domain, scope) and normalized not in seen:
            seen.add(normalized)
            found.append(normalized)
            if len(found) >= MAX_EMAILS:
                break
    return found


def generate_email_guesses(first: str, last: str, domain: str) -> list[str]:
    normalized = []
    for name in (first, last):
        ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
        normalized.append(re.sub(r"[^a-z0-9]", "", ascii_name.lower()))
    first_name, last_name = normalized
    if not first_name or not last_name:
        raise HarvestError("each name must contain ASCII letters or digits after normalization")
    values = {
        "first": first_name,
        "last": last_name,
        "f": first_name[0],
        "l": last_name[0],
    }
    return [f"{fmt.format(**values)}@{domain}" for fmt in COMMON_FORMATS]


def extract_emails_from_url(
    url: str,
    authorized_domain: str,
    limiter: Optional[RateLimiter] = None,
) -> list[str]:
    authorized_domain = validate_domain(authorized_domain)
    parsed = validate_scrape_url(url, authorized_domain)
    payload, response = request_bytes(
        urllib.parse.urlunparse(parsed),
        timeout=REQUEST_TIMEOUT,
        max_bytes=MAX_PAGE_BYTES,
        limiter=limiter,
    )
    content_type = response.headers.get_content_type().lower()
    if content_type not in ("text/html", "text/plain", "application/xhtml+xml"):
        raise HarvestError(f"refusing non-text content from {parsed.hostname} ({content_type})")
    charset = response.headers.get_content_charset() or "utf-8"
    try:
        text = payload.decode(charset, errors="replace")
    except LookupError as exc:
        raise HarvestError(f"unsupported character encoding from {parsed.hostname}") from exc
    return normalize_email_results(EMAIL_RE.findall(text), authorized_domain)


def scrape_github_org_members(
    org: str,
    limit: int = 25,
    token: Optional[str] = None,
    limiter: Optional[RateLimiter] = None,
) -> list[dict[str, str]]:
    """Return public profile emails for at most `limit` organization members."""
    org = validate_org(org)
    if not 1 <= limit <= MAX_GITHUB_USERS:
        raise HarvestError(f"GitHub limit must be between 1 and {MAX_GITHUB_USERS}")
    if token and (
        len(token) > 4096 or any(ord(character) < 32 or ord(character) == 127 for character in token)
    ):
        raise HarvestError("GITHUB_TOKEN contains invalid header characters or is too long")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"https://api.github.com/orgs/{urllib.parse.quote(org, safe='')}/members?per_page={limit}"
    payload, _ = request_bytes(url, headers=headers, limiter=limiter)
    members = parse_json(payload, "GitHub API")
    if not isinstance(members, list):
        raise HarvestError("GitHub API returned an unexpected member list")
    emails = []
    for member in members[:limit]:
        if not isinstance(member, dict) or not isinstance(member.get("login"), str):
            raise HarvestError("GitHub API returned an invalid member record")
        login = member["login"]
        if not re.fullmatch(r"[A-Za-z0-9-]{1,39}(?:\[bot\])?", login):
            raise HarvestError("GitHub API returned an invalid login")
        user_url = f"https://api.github.com/users/{urllib.parse.quote(login, safe='')}"
        user_payload, _ = request_bytes(user_url, headers=headers, limiter=limiter)
        user = parse_json(user_payload, "GitHub API")
        if not isinstance(user, dict):
            raise HarvestError("GitHub API returned an unexpected user record")
        email = user.get("email")
        if email:
            if not isinstance(email, str) or not EMAIL_RE.fullmatch(email):
                raise HarvestError(f"GitHub returned an invalid public email for @{login}")
            emails.append({"login": login, "email": email.lower()})
    return emails


def crtsh_email_search(
    domain: str,
    limiter: Optional[RateLimiter] = None,
) -> list[str]:
    domain = validate_domain(domain)
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    url = f"https://crt.sh/?{query}"
    payload, _ = request_bytes(url, limiter=limiter)
    entries = parse_json(payload, "crt.sh")
    if not isinstance(entries, list):
        raise HarvestError("crt.sh returned an unexpected result list")
    emails = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for value in entry.values():
            if isinstance(value, str):
                emails.extend(EMAIL_RE.findall(value))
    return normalize_email_results(emails, domain)


def read_names(path: str) -> list[str]:
    names = []
    try:
        with open(path, encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                if line_number > MAX_NAMES:
                    raise HarvestError(f"name file exceeds the {MAX_NAMES}-name limit")
                if len(line) > 512:
                    raise HarvestError(f"name on line {line_number} exceeds 512 characters")
                value = line.strip()
                if value:
                    names.append(value)
    except UnicodeError as exc:
        raise HarvestError(f"name file is not valid UTF-8: {path}") from exc
    return names


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect in-scope email addresses from explicitly authorized sources."
    )
    subparsers = parser.add_subparsers(dest="cmd")

    def add_authorization_option(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--authorized",
            action="store_true",
            required=True,
            help="confirm you are authorized to collect data from this scope",
        )
        command.add_argument("--out", help="write results as JSON to this file")

    guess_parser = subparsers.add_parser("guess", help="generate email format guesses")
    guess_parser.add_argument("domain", help="authorized target domain")
    guess_parser.add_argument("--names", required=True, help="UTF-8 file with one 'First Last' per line")
    add_authorization_option(guess_parser)

    scrape_parser = subparsers.add_parser("scrape", help="extract scoped emails from HTTPS pages")
    scrape_parser.add_argument("urls", nargs="+", help="HTTPS URLs on the authorized domain")
    scrape_parser.add_argument(
        "--authorized-domain",
        required=True,
        help="authorized registrable domain; URLs must use it or a subdomain",
    )
    add_authorization_option(scrape_parser)

    github_parser = subparsers.add_parser(
        "github", help="read public profile emails for GitHub organization members"
    )
    github_parser.add_argument("org", help="authorized GitHub organization")
    github_parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help=f"maximum member profiles to inspect (1-{MAX_GITHUB_USERS}; default: 25)",
    )
    add_authorization_option(github_parser)

    crt_parser = subparsers.add_parser(
        "crtsh", help="search certificate-transparency data for in-scope emails"
    )
    crt_parser.add_argument("domain", help="authorized target domain")
    add_authorization_option(crt_parser)
    return parser


def write_results(path: str, results: list[Any]) -> None:
    with open(path, "w", encoding="utf-8") as destination:
        json.dump(results, destination, indent=2)
        destination.write("\n")


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 2

    try:
        results: list[Any] = []
        if args.cmd == "guess":
            domain = validate_domain(args.domain)
            names = read_names(args.names)
            seen = set()
            for name in names:
                parts = name.split()
                if len(parts) < 2:
                    continue
                for email in generate_email_guesses(parts[0], parts[-1], domain):
                    if email not in seen:
                        seen.add(email)
                        results.append(email)
        elif args.cmd == "scrape":
            if len(args.urls) > MAX_URLS:
                raise HarvestError(f"at most {MAX_URLS} URLs may be supplied")
            domain = validate_domain(args.authorized_domain)
            for url in args.urls:
                validate_scrape_url(url, domain)
            limiter = RateLimiter()
            for url in args.urls:
                results.extend(extract_emails_from_url(url, domain, limiter))
            results = list(dict.fromkeys(results))
        elif args.cmd == "github":
            token = os.environ.get("GITHUB_TOKEN")
            results = scrape_github_org_members(args.org, args.limit, token, RateLimiter())
        elif args.cmd == "crtsh":
            results = crtsh_email_search(args.domain, RateLimiter())

        if args.out:
            write_results(args.out, results)
        if not args.out:
            for result in results:
                print(json.dumps(result, ensure_ascii=False) if isinstance(result, dict) else result)
        print(f"[+] {len(results)} result(s)")
        if args.out:
            print(f"[+] JSON results written to {args.out}")
        return 0
    except (HarvestError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
