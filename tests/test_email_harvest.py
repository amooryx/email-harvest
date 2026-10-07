import io
import json
import unittest
from unittest.mock import patch

import email_harvest as harvest


class FakeHeaders(dict):
    def get_content_type(self):
        return self.get("Content-Type", "text/html").split(";", 1)[0]

    def get_content_charset(self):
        return "utf-8"


class FakeResponse:
    def __init__(self, payload=b"", content_type="text/html"):
        self.payload = payload
        self.headers = FakeHeaders({"Content-Type": content_type})

    def read(self, length):
        return self.payload[:length]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None


class DomainScopeTests(unittest.TestCase):
    def test_domain_is_normalized(self):
        self.assertEqual(harvest.validate_domain("EXAMPLE.COM."), "example.com")

    def test_rejects_invalid_and_ip_scopes(self):
        for value in ("localhost", "example..com", "127.0.0.1", "-bad.example"):
            with self.subTest(value=value), self.assertRaises(harvest.HarvestError):
                harvest.validate_domain(value)

    def test_scope_matches_only_apex_and_subdomains(self):
        self.assertTrue(harvest.host_is_in_scope("example.com", "example.com"))
        self.assertTrue(harvest.host_is_in_scope("www.example.com", "example.com"))
        self.assertFalse(harvest.host_is_in_scope("notexample.com", "example.com"))
        self.assertFalse(harvest.host_is_in_scope("example.org", "example.com"))

    def test_scrape_requires_scoped_https_without_credentials_or_custom_ports(self):
        for url in (
            "http://example.com/team",
            "https://example.org/team",
            "https://example.com:8443/team",
            "https://user@example.com/team",
        ):
            with self.subTest(url=url), self.assertRaises(harvest.HarvestError):
                harvest.validate_scrape_url(url, "example.com")


class CollectionTests(unittest.TestCase):
    def test_guesses_normalize_names_and_domain(self):
        self.assertEqual(
            harvest.generate_email_guesses("Élodie", "O'Neil", "example.com")[0],
            "elodie.oneil@example.com",
        )

    def test_guesses_reject_empty_normalized_names(self):
        with self.assertRaises(harvest.HarvestError):
            harvest.generate_email_guesses("!!!", "Person", "example.com")

    @patch("email_harvest.request_bytes")
    def test_scrape_filters_to_scope_and_deduplicates(self, request_bytes):
        request_bytes.return_value = (
            b"Team: Alice@example.com alice@example.com external@gmail.com "
            b"also bob@sub.example.com",
            FakeResponse(),
        )
        actual = harvest.extract_emails_from_url(
            "https://www.example.com/team", "example.com"
        )
        self.assertEqual(actual, ["alice@example.com", "bob@sub.example.com"])
        request_bytes.assert_called_once()

    @patch("email_harvest.request_bytes")
    def test_scrape_rejects_non_text_content(self, request_bytes):
        request_bytes.return_value = (b"not a page", FakeResponse(content_type="image/png"))
        with self.assertRaisesRegex(harvest.HarvestError, "non-text"):
            harvest.extract_emails_from_url("https://example.com/", "example.com")

    @patch("email_harvest.request_bytes")
    def test_github_uses_env_token_header_and_limit(self, request_bytes):
        request_bytes.side_effect = [
            (json.dumps([{"login": "alice"}]).encode(), object()),
            (json.dumps({"email": "Alice@Example.com", "name": "Private name"}).encode(), object()),
        ]
        results = harvest.scrape_github_org_members("example-org", 1, "secret-token")
        self.assertEqual(results, [{"login": "alice", "email": "alice@example.com"}])
        self.assertEqual(request_bytes.call_args_list[0].kwargs["headers"]["Authorization"], "Bearer secret-token")
        self.assertIn("per_page=1", request_bytes.call_args_list[0].args[0])

    def test_github_limit_is_bounded(self):
        with self.assertRaisesRegex(harvest.HarvestError, "between 1 and"):
            harvest.scrape_github_org_members("example-org", 101)

    def test_github_rejects_tokens_with_header_controls(self):
        with self.assertRaisesRegex(harvest.HarvestError, "invalid header"):
            harvest.scrape_github_org_members("example-org", 1, "token\r\nInjected: yes")

    @patch("email_harvest.request_bytes")
    def test_crtsh_search_encodes_scope_and_filters_results(self, request_bytes):
        request_bytes.return_value = (
            json.dumps([
                {"name_value": "admin@example.com\nexternal@gmail.com"},
                {"email": "ops@sub.example.com"},
            ]).encode(),
            object(),
        )
        results = harvest.crtsh_email_search("example.com")
        self.assertEqual(results, ["admin@example.com", "ops@sub.example.com"])
        self.assertIn("q=%25.example.com", request_bytes.call_args.args[0])

    def test_json_errors_are_reported(self):
        with self.assertRaisesRegex(harvest.HarvestError, "invalid JSON"):
            harvest.parse_json(b"{", "test")


class RequestSafetyTests(unittest.TestCase):
    @patch("email_harvest.ensure_public_host")
    @patch("email_harvest.urllib.request.build_opener")
    def test_request_is_bounded_and_does_not_use_proxy(self, build_opener, ensure_public_host):
        response = FakeResponse(b"ok")
        opener = type("Opener", (), {"open": lambda self, request, timeout: response})()
        build_opener.return_value = opener

        payload, _ = harvest.request_bytes("https://example.com", max_bytes=10)

        self.assertEqual(payload, b"ok")
        ensure_public_host.assert_called_once_with("example.com")
        handlers = build_opener.call_args.args
        self.assertIsInstance(handlers[0], harvest.urllib.request.ProxyHandler)
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], harvest.NoRedirectHandler)

    @patch("email_harvest.ensure_public_host")
    @patch("email_harvest.urllib.request.build_opener")
    def test_oversized_content_length_is_rejected(self, build_opener, ensure_public_host):
        response = FakeResponse()
        response.headers["Content-Length"] = "11"
        opener = type("Opener", (), {"open": lambda self, request, timeout: response})()
        build_opener.return_value = opener

        with self.assertRaisesRegex(harvest.HarvestError, "10-byte limit"):
            harvest.request_bytes("https://example.com", max_bytes=10)

    @patch("email_harvest.socket.getaddrinfo", return_value=[
        (None, None, None, None, ("192.168.1.2", 443))
    ])
    def test_private_dns_result_is_rejected(self, getaddrinfo):
        with self.assertRaisesRegex(harvest.HarvestError, "non-public"):
            harvest.ensure_public_host("internal.example")


class CliTests(unittest.TestCase):
    def test_collection_requires_explicit_authorization(self):
        parser = harvest.build_parser()
        with self.assertRaises(SystemExit) as raised:
            parser.parse_args(["crtsh", "example.com"])
        self.assertEqual(raised.exception.code, 2)

    @patch("builtins.open")
    def test_name_file_is_bounded(self, open_file):
        open_file.return_value.__enter__.return_value = io.StringIO(
            "\n".join(["First Last"] * (harvest.MAX_NAMES + 1))
        )
        with self.assertRaisesRegex(harvest.HarvestError, "name limit"):
            harvest.read_names("names.txt")


if __name__ == "__main__":
    unittest.main()
